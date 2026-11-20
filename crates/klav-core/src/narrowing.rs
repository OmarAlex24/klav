//! Whether a new grant policy only narrows the one it replaces (ADR 0033,
//! amendment of 2026-11-10, F3).
//!
//! Widening a grant asks for presence; narrowing it does not (P8). The
//! check is **prudent**: it says "narrows" only when it can show that, for
//! every request, [`evaluate`](crate::policy::evaluate) gives the new policy
//! an effect at least as strict as the old one (`allow` < `ask` < `deny`).
//! Anything it cannot show counts as widening, and asks.
//!
//! It works on the effect `evaluate` computes (ADR 0006), not on the rules
//! as written: removing the last rule of a permission falls back to its
//! default, which may be broader (removing "`fill` only on github.com"
//! lets `fill` through everywhere, and that widens).
//!
//! # How it decides, per permission
//!
//! * The old policy has no rules for it: every request got the default
//!   `d`. The new one narrows if it has no rules either, or if every new
//!   rule's effect is at least `d` (the result is the strictest matching
//!   rule, or `deny` out of scope).
//! * The old policy has rules: a request got `deny` out of scope, or at most
//!   the loosest-to-strictest maximum of the old effects. The new one
//!   narrows if:
//!   - it has no rules and its default is `deny`, or its default is at
//!     least every old effect and some old rule always applied (empty
//!     scope, no expiry), so the old one was never out of scope;
//!   - or every new rule that is not `deny` is at least as strict as every
//!     old rule, and is covered by an old rule: its scope is inside that
//!     rule's scope (dimension by dimension, as a subset of the same
//!     values) and that rule lives at least as long. Then wherever the new
//!     rule applies, the old one applied too and was never stricter.
//!
//! Before those two, the simplest case: the new rules are the old ones with
//! some effects made stricter and some `deny` rules added (in any order).
//! The policy's own expiry must not move later (none is "never").
//!
//! Projects are not part of a [`Policy`]: the caller checks that the new
//! grant's projects are among the old ones.

use crate::policy::{Effect, Permission, Policy, Rule, Scope};

/// Whether `new` only narrows `old` (see the module docs). Prudent: `false`
/// when it cannot show it.
pub fn policy_narrows(old: &Policy, new: &Policy) -> bool {
    expiry_narrows(old.expires_at, new.expires_at)
        && Permission::ALL
            .iter()
            .all(|p| permission_narrows(old, new, *p))
}

/// Whether an expiry moved earlier or stayed (`None` is "never").
pub fn expiry_narrows(old: Option<u64>, new: Option<u64>) -> bool {
    match (old, new) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(old), Some(new)) => new <= old,
    }
}

/// Whether `new` only narrows `old` for `permission`, leaving the
/// policies' own expiry aside ([`expiry_narrows`]).
pub fn permission_narrows(old: &Policy, new: &Policy, permission: Permission) -> bool {
    // Only an approved task allows them: `deny` under any grant.
    if permission.requires_task() {
        return true;
    }
    let old_rules = rules_for(old, permission);
    let new_rules = rules_for(new, permission);
    if only_tightened(&old_rules, &new_rules) {
        return true;
    }
    let default = permission.default_effect();
    let Some(old_max) = old_rules.iter().map(|r| r.effect).max() else {
        return new_rules.iter().all(|r| r.effect >= default);
    };
    if new_rules.is_empty() {
        return default == Effect::Deny
            || (default >= old_max && old_rules.iter().any(|r| always_applies(r)));
    }
    new_rules.iter().all(|n| {
        n.effect == Effect::Deny || (n.effect >= old_max && old_rules.iter().any(|o| covers(o, n)))
    })
}

fn rules_for(policy: &Policy, permission: Permission) -> Vec<&Rule> {
    policy
        .rules
        .iter()
        .filter(|r| r.permission == permission)
        .collect()
}

/// Whether `new` is `old` with some effects made stricter and some `deny`
/// rules added: each old rule keeps a twin with the same scope and expiry
/// and an effect at least as strict, and every other new rule denies.
/// Then a request matches the twins of the old rules it matched (each at
/// least as strict), and one the old rules left out of scope matches only
/// `deny` rules, or none. The same rules in another order pass.
fn only_tightened(old: &[&Rule], new: &[&Rule]) -> bool {
    let mut left: Vec<&Rule> = new.to_vec();
    for o in old {
        let twin = left
            .iter()
            .enumerate()
            .filter(|(_, n)| {
                n.scope == o.scope && n.expires_at == o.expires_at && n.effect >= o.effect
            })
            .min_by_key(|(_, n)| n.effect)
            .map(|(i, _)| i);
        match twin {
            Some(i) => {
                left.swap_remove(i);
            }
            None => return false,
        }
    }
    left.iter().all(|n| n.effect == Effect::Deny)
}

/// A rule that matches every request, forever.
fn always_applies(rule: &Rule) -> bool {
    rule.expires_at.is_none() && rule.scope == Scope::default()
}

/// Whether `old` applies wherever and whenever `new` does.
fn covers(old: &Rule, new: &Rule) -> bool {
    let lives = match (old.expires_at, new.expires_at) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(o), Some(n)) => n <= o,
    };
    lives && scope_inside(&new.scope, &old.scope)
}

/// Whether every request `inner` matches is matched by `outer`: each of
/// `outer`'s dimensions is empty (no constraint), or `inner` constrains it
/// to a subset of the same values. Prudent: `*.github.com` is not seen as
/// inside `*.com`, only as itself.
fn scope_inside(inner: &Scope, outer: &Scope) -> bool {
    fn subset<T: PartialEq>(inner: &[T], outer: &[T]) -> bool {
        outer.is_empty() || (!inner.is_empty() && inner.iter().all(|x| outer.contains(x)))
    }
    subset(&inner.vaults, &outer.vaults)
        && subset(&inner.projects, &outer.projects)
        && subset(&inner.tags, &outer.tags)
        && subset(&inner.domains, &outer.domains)
        && subset(&inner.hours, &outer.hours)
        && subset(&inner.items, &outer.items)
        && subset(&inner.methods, &outer.methods)
        && subset(&inner.path_prefixes, &outer.path_prefixes)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::ids::{ItemId, ProjectId, VaultId};
    use crate::model::reference::Selector;
    use crate::policy::{Request, Target, TimeWindow, evaluate};

    const NOW: u64 = 1_800_000_000;

    fn rule(permission: Permission, effect: Effect) -> Rule {
        Rule::new(permission, effect)
    }

    fn on_sites(permission: Permission, effect: Effect, sites: &[&str]) -> Rule {
        Rule {
            scope: Scope {
                domains: sites.iter().map(|s| s.parse().unwrap()).collect(),
                ..Scope::default()
            },
            ..Rule::new(permission, effect)
        }
    }

    fn with_hours(mut rule: Rule, hours: &[&str]) -> Rule {
        rule.scope.hours = hours.iter().map(|h| h.parse().unwrap()).collect();
        rule
    }

    fn policy(rules: Vec<Rule>) -> Policy {
        Policy {
            rules,
            expires_at: None,
        }
    }

    /// What `klav agent approve --hours …` writes: a rule for every
    /// grantable permission (its default when it had none), each with the
    /// windows.
    fn scheduled(explicit: Vec<Rule>, hours: &[&str]) -> Policy {
        let mut rules = explicit;
        for permission in Permission::GRANTABLE {
            if !rules.iter().any(|r| r.permission == permission) {
                rules.push(rule(permission, permission.default_effect()));
            }
        }
        policy(rules.into_iter().map(|r| with_hours(r, hours)).collect())
    }

    #[test]
    fn the_same_policy_narrows_in_any_order() {
        let a = policy(vec![
            rule(Permission::Reveal, Effect::Ask),
            on_sites(Permission::Fill, Effect::Allow, &["github.com"]),
        ]);
        let mut b = a.clone();
        b.rules.reverse();
        assert!(policy_narrows(&a, &b));
        assert!(policy_narrows(&Policy::default(), &Policy::default()));
    }

    #[test]
    fn a_stricter_effect_narrows_and_a_looser_one_widens() {
        let ask = policy(vec![rule(Permission::Reveal, Effect::Ask)]);
        let deny = policy(vec![rule(Permission::Reveal, Effect::Deny)]);
        let allow = policy(vec![rule(Permission::Reveal, Effect::Allow)]);
        assert!(policy_narrows(&ask, &deny));
        assert!(!policy_narrows(&ask, &allow));
        assert!(!policy_narrows(&deny, &ask));
        // From the default (`reveal` denies): any rule that is not `deny`
        // widens.
        assert!(!policy_narrows(&Policy::default(), &ask));
        assert!(policy_narrows(&Policy::default(), &deny));
        // `list` allows by default: asking narrows.
        assert!(policy_narrows(
            &Policy::default(),
            &policy(vec![rule(Permission::List, Effect::Ask)])
        ));
    }

    /// ADR 0033 F3: removing the last rule of a permission goes back to its
    /// default, which may be broader.
    #[test]
    fn removing_the_last_rule_falls_back_to_the_default() {
        let github = policy(vec![on_sites(
            Permission::Fill,
            Effect::Allow,
            &["github.com"],
        )]);
        // `fill` allows everywhere by default: widens.
        assert!(!policy_narrows(&github, &Policy::default()));
        // `reveal` denies by default: narrows.
        let ask = policy(vec![rule(Permission::Reveal, Effect::Ask)]);
        assert!(policy_narrows(&ask, &Policy::default()));
        // `update` asks by default, and a plain `ask` rule always applied:
        // the same.
        let update = policy(vec![rule(Permission::Update, Effect::Ask)]);
        assert!(policy_narrows(&update, &Policy::default()));
        let update_allow = policy(vec![rule(Permission::Update, Effect::Allow)]);
        assert!(policy_narrows(&update_allow, &Policy::default()));
    }

    #[test]
    fn fewer_sites_narrow_and_more_or_none_widen() {
        let two = policy(vec![on_sites(
            Permission::Fill,
            Effect::Allow,
            &["github.com", "*.gitlab.com"],
        )]);
        let one = policy(vec![on_sites(
            Permission::Fill,
            Effect::Allow,
            &["github.com"],
        )]);
        let three = policy(vec![on_sites(
            Permission::Fill,
            Effect::Allow,
            &["github.com", "*.gitlab.com", "bitbucket.org"],
        )]);
        let anywhere = policy(vec![rule(Permission::Fill, Effect::Allow)]);
        assert!(policy_narrows(&two, &one));
        assert!(!policy_narrows(&two, &three));
        // From a list to none: everywhere.
        assert!(!policy_narrows(&two, &anywhere));
        assert!(policy_narrows(&anywhere, &two));
        // Prudent: a narrower pattern that is not the same value counts as
        // widening.
        let sub = policy(vec![on_sites(
            Permission::Fill,
            Effect::Allow,
            &["api.github.com"],
        )]);
        let wild = policy(vec![on_sites(
            Permission::Fill,
            Effect::Allow,
            &["*.github.com"],
        )]);
        assert!(!policy_narrows(&wild, &sub));
    }

    #[test]
    fn fewer_hours_narrow_and_none_widen() {
        let week = scheduled(
            vec![],
            &["mon-fri 09:00-18:00 -06:00", "sat 10:00-14:00 -06:00"],
        );
        let weekdays = scheduled(vec![], &["mon-fri 09:00-18:00 -06:00"]);
        let always = Policy::default();
        assert!(policy_narrows(&week, &weekdays));
        assert!(!policy_narrows(&weekdays, &week));
        assert!(!policy_narrows(&weekdays, &always));
        assert!(policy_narrows(&always, &weekdays));
    }

    #[test]
    fn expiry_only_narrows_when_it_comes_sooner() {
        let at = |t| Policy {
            rules: Vec::new(),
            expires_at: t,
        };
        assert!(policy_narrows(&at(Some(10)), &at(Some(5))));
        assert!(policy_narrows(&at(Some(10)), &at(Some(10))));
        assert!(!policy_narrows(&at(Some(10)), &at(Some(11))));
        assert!(!policy_narrows(&at(Some(10)), &at(None)));
        assert!(policy_narrows(&at(None), &at(Some(10))));
    }

    /// ADR 0006 §4: a lapsed rule fails closed. A rule that lives longer
    /// widens; one that lapses sooner narrows.
    #[test]
    fn a_rule_that_lives_longer_widens() {
        let until = |t: Option<u64>| {
            policy(vec![Rule {
                expires_at: t,
                ..rule(Permission::Reveal, Effect::Allow)
            }])
        };
        assert!(policy_narrows(&until(Some(10)), &until(Some(5))));
        assert!(!policy_narrows(&until(Some(10)), &until(Some(20))));
        assert!(!policy_narrows(&until(Some(10)), &until(None)));
        assert!(policy_narrows(&until(None), &until(Some(10))));
    }

    #[test]
    fn a_new_deny_rule_always_narrows() {
        let base = policy(vec![on_sites(Permission::Fill, Effect::Allow, &["a.com"])]);
        let mut more = base.clone();
        more.rules
            .push(on_sites(Permission::Fill, Effect::Deny, &["b.com"]));
        assert!(policy_narrows(&base, &more));
    }

    // ---- the property test: "narrows" never lets a request through more.

    const SITES: [&str; 4] = ["a.com", "b.com", "*.c.com", "x.c.com"];
    const TAGS: [&str; 2] = ["prod", "dev"];
    const HOURS: [&str; 3] = [
        "mon-fri 09:00-18:00 +00:00",
        "daily 22:00-02:00 +00:00",
        "sat,sun 00:00-00:00 -06:00",
    ];
    const T0: u64 = NOW;

    fn vault(i: u8) -> VaultId {
        VaultId::from_bytes([i + 1; 16])
    }
    fn project(i: u8) -> ProjectId {
        ProjectId::from_bytes([i + 10; 16])
    }
    fn item(i: u8) -> ItemId {
        ItemId::from_bytes([i + 20; 16])
    }

    fn effect() -> impl Strategy<Value = Effect> {
        prop_oneof![Just(Effect::Allow), Just(Effect::Ask), Just(Effect::Deny)]
    }

    fn permission() -> impl Strategy<Value = Permission> {
        prop::sample::select(Permission::ALL.to_vec())
    }

    fn picks<T: Clone + PartialEq + std::fmt::Debug + 'static>(
        from: Vec<T>,
    ) -> impl Strategy<Value = Vec<T>> {
        let n = from.len();
        prop::collection::vec(prop::sample::select(from), 0..=n.min(2)).prop_map(|mut v| {
            v.dedup();
            v
        })
    }

    fn expiry() -> impl Strategy<Value = Option<u64>> {
        prop_oneof![
            3 => Just(None),
            1 => (0u64..4).prop_map(|k| Some(T0 + k * 3600)),
        ]
    }

    fn scope() -> impl Strategy<Value = Scope> {
        (
            picks(vec![Selector::Id(vault(0)), Selector::Id(vault(1))]),
            picks(vec![Selector::Id(project(0)), Selector::Id(project(1))]),
            picks(TAGS.iter().map(|t| (*t).to_owned()).collect()),
            picks(SITES.iter().map(|s| s.parse().unwrap()).collect()),
            picks(
                HOURS
                    .iter()
                    .map(|h| h.parse::<TimeWindow>().unwrap())
                    .collect(),
            ),
            picks(vec![item(0), item(1)]),
        )
            .prop_map(|(vaults, projects, tags, domains, hours, items)| Scope {
                vaults,
                projects,
                tags,
                domains,
                hours,
                items,
                ..Scope::default()
            })
    }

    fn a_rule() -> impl Strategy<Value = Rule> {
        (permission(), effect(), scope(), expiry()).prop_map(|(permission, effect, scope, e)| {
            Rule {
                permission,
                effect,
                scope,
                expires_at: e,
            }
        })
    }

    fn a_policy() -> impl Strategy<Value = Policy> {
        (prop::collection::vec(a_rule(), 0..5), expiry())
            .prop_map(|(rules, expires_at)| Policy { rules, expires_at })
    }

    fn a_request() -> impl Strategy<Value = Request> {
        (
            permission(),
            0u8..2,
            0u8..2,
            picks(TAGS.iter().map(|t| (*t).to_owned()).collect()),
            prop::option::of(prop::sample::select(vec![
                "a.com", "b.com", "x.c.com", "y.c.com", "d.com",
            ])),
            prop::option::of(0u8..3),
            0u64..(7 * 24 * 3600),
        )
            .prop_map(|(permission, v, p, tags, domain, it, offset)| Request {
                permission,
                vault: Target {
                    id: vault(v),
                    name: format!("v{v}"),
                },
                project: Target {
                    id: project(p),
                    name: format!("p{p}"),
                },
                tags,
                domain: domain.map(str::to_owned),
                item: it.map(item),
                method: Some("GET".into()),
                path: Some("/v1".into()),
                // Before, at and after each expiry, across a week of hours.
                now: T0 - 3600 + offset,
            })
    }

    /// Changes that must always read as narrowing: they are what the
    /// prudent check is built to see (against a vacuous "never narrows").
    fn narrowing_change(old: &Policy, how: u8, p: Permission, at: u64) -> Policy {
        let mut new = old.clone();
        match how % 4 {
            // A `deny` rule more.
            0 => new.rules.push(Rule::new(p, Effect::Deny)),
            // The policy lapses sooner.
            1 => new.expires_at = Some(old.expires_at.map_or(at, |t| t.min(at))),
            // One permission denied outright.
            2 => {
                new.rules.retain(|r| r.permission != p);
                new.rules.push(Rule::new(p, Effect::Deny));
            }
            // Rules reordered.
            _ => new.rules.reverse(),
        }
        new
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn narrows_never_gives_a_request_more(
            old in a_policy(),
            new in a_policy(),
            requests in prop::collection::vec(a_request(), 32),
        ) {
            if policy_narrows(&old, &new) {
                for r in &requests {
                    let before = evaluate(&old, r).effect;
                    let after = evaluate(&new, r).effect;
                    prop_assert!(after >= before, "{r:?}: {before:?} -> {after:?}");
                }
            }
        }

        #[test]
        fn a_narrowing_change_is_seen_and_holds(
            old in a_policy(),
            how in 0u8..4,
            p in permission(),
            hours in 0u64..4,
            requests in prop::collection::vec(a_request(), 32),
        ) {
            let new = narrowing_change(&old, how, p, T0 + hours * 3600);
            prop_assert!(policy_narrows(&old, &new));
            for r in &requests {
                prop_assert!(evaluate(&new, r).effect >= evaluate(&old, r).effect);
            }
        }

        /// The same policy with one rule loosened or tightened: whatever
        /// the check says, a "narrows" holds for every request.
        #[test]
        fn one_rule_changed_holds_when_it_narrows(
            old in a_policy(),
            index in 0usize..5,
            e in effect(),
            requests in prop::collection::vec(a_request(), 32),
        ) {
            let mut new = old.clone();
            if let Some(rule) = new.rules.get_mut(index) {
                rule.effect = e;
            }
            if policy_narrows(&old, &new) {
                for r in &requests {
                    prop_assert!(evaluate(&new, r).effect >= evaluate(&old, r).effect);
                }
            }
        }
    }
}
