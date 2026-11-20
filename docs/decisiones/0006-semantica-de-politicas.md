# 0006 · Evaluation semantics of agent policies

- Status: accepted
- Date: 2026-11-02

## Context
The design (§5.2 and §5.3) defines the permissions, their defaults, the `allow`/`ask`/`deny` effects, and that each permission can be scoped by vault, project, tag, domain, schedule and expiry. It doesn't say what happens when several rules apply, when a rule scopes a permission that is allowed by default, or what happens when a rule expires. Phase 1 implements evaluation as a pure function (`klav_core::policy::evaluate`) and needs to pin those rules down.

## Decision
1. **No rules, default value.** If the policy has no rules for a permission, the table in §5.2 applies: `list`, `fill`, `inject` and `create` → `allow`; `totp` and `update` → `ask`; `reveal` and `delete` → `deny`.
2. **With rules, only the rules count.** If there is at least one rule for the permission, the default no longer applies. So a `fill: allow` rule scoped to `*.github.com` means "`fill` only on GitHub", not "`fill` everywhere, and also on GitHub".
3. **The most restrictive wins.** Among the rules that apply (not expired and with a matching scope), the most restrictive effect wins: `deny` > `ask` > `allow`. The order of the rules doesn't matter.
4. **Out of scope, `deny`.** If there are rules for the permission but none applies, the answer is `deny`.
5. **Expiry fails closed.** An expired rule doesn't apply, but it still counts as a "rule for the permission". When a temporary rule expires, the permission stays at `deny` and does not go back to the default, which could be broader. If the whole policy expires, everything is `deny`.
6. **Scope.** Every non-empty dimension must match (AND across dimensions, OR within each one). Vaults and projects match by ID or by name (case-insensitive), and tags case-insensitively. Domains use patterns compatible with Chrome extension *match patterns*: `ejemplo.com` is exact and `*.ejemplo.com` includes `ejemplo.com` and all its subdomains. `*.com` and wildcards in the middle are rejected. The Public Suffix List is not consulted.
7. **Schedule** (§5.2 of the design) is out of phase 1. It will be added in phase 4 as another scope dimension.
8. The "approve once" and "approve for 15 min" **approvals** (§5.3) are not rules: they will be their own signed objects in phase 4.

## Consequences
- Scoping a permission never widens it by accident: adding a `deny` rule never makes a decision more permissive (property checked with proptest).
- Downside: a temporary `update: allow` rule leaves `update` at `deny` (not `ask`) when it expires. If going back to the default is preferred, point 5 has to change. That change is only safe if the default is not broader than what the rule scoped.
- The extension (phase 5) must interpret domain patterns the same way as `DomainPattern::matches`.
