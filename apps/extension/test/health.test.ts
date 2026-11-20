// @vitest-environment jsdom
// «Salud» in the popup (ADR 0022 §4, §6): the report's four sections, the
// fix button, what the popup offers (the logins left checked, never a
// blocked one, under a neutral title) and how a running task's sites read.
import { afterEach, describe, expect, it } from "vitest";
import type { HealthItem, OfferRow, SiteProgress, TaskCard, VaultHealth } from "../src/shared/protocol";
import { healthSections, isFixTask, offerRequest, offerSteps, pickedItems, progressCounts, siteLabel } from "../src/ui/health";
import { t } from "../src/shared/i18n";
import { useLocale } from "./setup";

afterEach(() => {
  useLocale("en");
});

const item = (title: string, host: string): HealthItem => ({
  id: `id-${title}`,
  vault_id: "v",
  project_id: "p",
  reference: `klav://Personal/General/${title}`,
  kind: "login",
  title,
  username: "ana",
  hosts: [host],
  field: "password",
  field_label: "Password",
});

const report: VaultHealth = {
  checked_at: 0,
  items: 6,
  passwords: 6,
  reused: [{ items: [item("Bank", "bank.example"), item("Shop", "shop.example")] }],
  weak: [{ item: item("Forum", "forum.example"), score: 1 }],
  old: [{ item: item("Mail", "mail.example"), since_ms: Date.UTC(2024, 0, 2), days: 700, source: "created" }],
  breaches: { status: "off" },
};

const row = (id: string, host: string, over: Partial<OfferRow> = {}): OfferRow => ({
  item_id: id,
  vault_id: "v",
  project_id: "p",
  reference: `klav://Personal/General/${id}`,
  title: id,
  hosts: [host],
  group: 1,
  permissions: ["rotate"],
  ...over,
});

describe("the report", () => {
  it("shows reused, weak, old and breached, and the fix button", () => {
    const fixes: string[] = [];
    const el = healthSections(report, { breach_check: false, notice: "" }, { fix: () => fixes.push("fix"), breach: () => Promise.resolve() });
    document.body.replaceChildren(el);
    const text = el.textContent;
    for (const key of ["health_reused", "health_weak", "health_old"] as const) expect(text).toContain(t(key, 1));
    expect(text).toContain(t("health_breached"));
    expect(text).toContain(t("health_same_in", 2));
    expect(text).toContain("Bank");
    expect(text).toContain(t("health_score", 1));
    // The breach check is off: the switch with what it sends.
    const box = el.querySelector<HTMLInputElement>("#breach-check");
    expect(box?.checked).toBe(false);
    expect(text).toContain("api.pwnedpasswords.com");
    el.querySelector<HTMLButtonElement>(".health-fix")?.click();
    expect(fixes).toEqual(["fix"]);
  });

  it("offers no fix without reused passwords, and says when all is well", () => {
    const clean: VaultHealth = { ...report, reused: [], weak: [], old: [], breaches: { status: "checked", found: [], queries: 3 } };
    const el = healthSections(clean, undefined, { fix: () => undefined });
    expect(el.querySelector(".health-fix")).toBeNull();
    expect(el.textContent).toContain(t("health_clean"));
    expect(el.textContent).toContain(t("health_breached_none"));
  });

  it("reads in Spanish", () => {
    useLocale("es");
    const el = healthSections(report, undefined, { fix: () => undefined });
    expect(el.textContent).toContain("Repetidas · 1");
    expect(el.querySelector(".health-fix")?.textContent).toBe("Arreglar mis contraseñas repetidas");
  });
});

describe("the offer", () => {
  const rows = [row("Bank", "bank.example"), row("Notes", "", { hosts: [], blocked: "no_site" }), row("Shop", "shop.example", { permissions: ["rotate", "totp"] })];

  it("sends the logins left checked, never a blocked one", () => {
    const checked = new Set(["Bank", "Notes"]);
    expect(pickedItems(rows, (id) => checked.has(id))).toEqual(["Bank"]);
    const request = offerRequest("agent-1", rows, () => true, 3600);
    expect(request).toEqual({
      agent: "agent-1",
      items: ["Bank", "Shop"],
      task: t("health_offer_task"),
      reason: t("health_offer_reason"),
      duration_secs: 3600,
    });
  });

  it("tells the agent nothing about reuse", () => {
    for (const lang of ["en", "es"]) {
      useLocale(lang);
      const { task, reason } = offerRequest("a", rows, () => true, 3600);
      expect(`${task ?? ""} ${reason ?? ""}`.toLowerCase()).not.toMatch(/reuse|repet|share|compart|same|misma/);
    }
  });

  it("lasts 2 hours unless the person picks otherwise, at most a day", () => {
    const steps = offerSteps();
    expect(steps[0]).toBe(7200);
    expect(Math.max(...steps)).toBe(86_400);
    expect(new Set(steps).size).toBe(steps.length);
  });
});

describe("a running task", () => {
  const site = (state: SiteProgress["state"], started = false): SiteProgress => ({ item_id: "i", hosts: ["bank.example"], state, started });

  it("reads each site as changed, in progress, pending or failed", () => {
    expect(siteLabel(site("changed"))).toBe("health_site_changed");
    expect(siteLabel(site("pending", true))).toBe("health_site_running");
    expect(siteLabel(site("pending"))).toBe("health_site_pending");
    expect(siteLabel(site("failed"))).toBe("health_site_failed");
    expect(progressCounts([site("changed"), site("pending", true), site("pending"), site("failed")])).toEqual({ changed: 1, pending: 2, failed: 1 });
  });

  it("follows only offered, running tasks with rotate", () => {
    const card: TaskCard = {
      id: "t",
      status: "approved",
      agent_id: "a",
      agent: "bot",
      task: "Change passwords",
      reason: "",
      request_digest: "",
      duration_secs: 3600,
      created_at: 0,
      decide_by: 0,
      revision: 1,
      expires_at: 10_000,
      offered: true,
      rows: [
        {
          vault_id: "v",
          project_id: "p",
          item_id: "i",
          reference: "r",
          missing: false,
          domain_mismatch: false,
          domains: ["bank.example"],
          permissions: [{ permission: "rotate", checked: true, asked: false, added_by_klav: false, denied_by_policy: false }],
        },
      ],
    };
    expect(isFixTask(card, 5000)).toBe(true);
    expect(isFixTask(card, 10_000)).toBe(false);
    expect(isFixTask({ ...card, offered: false }, 5000)).toBe(false);
    expect(isFixTask({ ...card, status: "ended" }, 5000)).toBe(false);
  });
});
