//! `klav agent approve --env NAME=allow|ask|deny` (ADR 0032 §4.3 and §4.5):
//! per-environment `inject` rules, scoped by each environment's item ID,
//! on the usual grant and policy model (ADR 0006).
//!
//! Two rules of ADR 0006 shape the translation:
//!
//! * **§2:** as soon as a permission has rules, its default stops applying.
//!   So when `inject` had no rule before, its default goes in first as an
//!   explicit rule with no scope, and unrelated items keep it.
//! * **§3:** among the rules that apply, the most restrictive wins. An
//!   environment cannot end up more open than a broader rule that also
//!   covers it: Klav says so and proposes narrowing that rule by items.
//!
//! A protected environment never goes in `allow` (`ask once` at most), and
//! the person's client adds `ask once` for it and the items it protects on
//! its own when it signs ([`klav_client`]'s `protect_grant`).

use klav_client::ProjectSummary;
use klav_client::environments::{EnvironmentListing, VariableOrigin};
use klav_core::ids::{ItemId, ProjectId, VaultId};
use klav_core::model::Reference;
use klav_core::model::Selector as RefSelector;
use klav_core::policy::{self, Decision, Effect, Permission, Policy, Reason, Rule, Scope, Target};

use crate::cli::AgentApproveArgs;
use crate::context::Ctx;
use crate::error::{CliResult, usage};

/// One `--env` of the command line, resolved to its environment.
#[derive(Debug, Clone)]
pub(crate) struct EnvRule {
    /// As written (`NAME` or `Vault/Project/NAME`).
    pub(crate) spec: String,
    /// The environment.
    pub(crate) listing: EnvironmentListing,
    /// What the person asked for it.
    pub(crate) effect: Effect,
}

impl EnvRule {
    /// The `inject` rule for it: scoped by its project and its item ID;
    /// `ask` on a protected environment is `ask once` (ADR 0032 §4.2).
    pub(crate) fn rule(&self) -> Rule {
        Rule {
            scope: Scope {
                projects: vec![RefSelector::Id(self.listing.project_id)],
                items: vec![self.listing.id],
                ..Scope::default()
            },
            once: self.effect == Effect::Ask && self.listing.protected,
            ..Rule::new(Permission::Inject, self.effect)
        }
    }

    fn wanted(&self) -> Decision {
        Decision {
            effect: self.effect,
            reason: Reason::Default,
            once: self.effect == Effect::Ask && self.listing.protected,
        }
    }
}

fn effect_of(text: &str) -> Option<Effect> {
    match text.trim().to_ascii_lowercase().as_str() {
        "allow" => Some(Effect::Allow),
        "ask" => Some(Effect::Ask),
        "deny" => Some(Effect::Deny),
        _ => None,
    }
}

/// Whether `listing` is in a project the grant shares: `--project` names
/// (`vault/project`, any case) or `--vault` names.
fn shared(listing: &EnvironmentListing, projects: &[String], vaults: &[String]) -> bool {
    projects.iter().any(|p| {
        p.split_once('/').is_some_and(|(v, n)| {
            v.eq_ignore_ascii_case(&listing.vault) && n.eq_ignore_ascii_case(&listing.project)
        })
    }) || vaults
        .iter()
        .any(|v| v.eq_ignore_ascii_case(&listing.vault))
}

/// Resolves the `--env` flags against the environments of the projects
/// the grant shares (`listings`): each must name exactly one, once, and a
/// protected one is never `allow`.
pub(crate) fn resolve(
    specs: &[String],
    projects: &[String],
    vaults: &[String],
    listings: &[EnvironmentListing],
) -> CliResult<Vec<EnvRule>> {
    let mut out: Vec<EnvRule> = Vec::new();
    for spec in specs {
        let (name, effect) = spec.rsplit_once('=').ok_or_else(|| {
            usage(format!(
                "--env expects NAME=allow|ask|deny (or VAULT/PROJECT/NAME=…), got {spec:?}"
            ))
        })?;
        let effect = effect_of(effect).ok_or_else(|| {
            usage(format!(
                "--env {name}: use allow, ask or deny, not {effect:?}"
            ))
        })?;
        let (place, env) = match name.rsplit_once('/') {
            Some((place, env)) => (Some(place), env),
            None => (None, name),
        };
        let found: Vec<&EnvironmentListing> = listings
            .iter()
            .filter(|l| l.name == env)
            .filter(|l| match place {
                Some(place) => place.split_once('/').is_some_and(|(v, p)| {
                    v.eq_ignore_ascii_case(&l.vault) && p.eq_ignore_ascii_case(&l.project)
                }),
                None => true,
            })
            .filter(|l| shared(l, projects, vaults))
            .collect();
        let listing = match found.as_slice() {
            [one] => (*one).clone(),
            [] => {
                return Err(usage(format!(
                    "--env {name}: no environment {env:?} in the projects this grant shares (--project, --vault)"
                )));
            }
            several => {
                let places: Vec<String> = several
                    .iter()
                    .map(|l| format!("{}/{}/{}", l.vault, l.project, l.name))
                    .collect();
                return Err(usage(format!(
                    "--env {name}: several projects have it ({}): write VAULT/PROJECT/{env}=…",
                    places.join(", ")
                )));
            }
        };
        if out.iter().any(|r| r.listing.id == listing.id) {
            return Err(usage(format!("--env {name}: given twice")));
        }
        if listing.protected && effect == Effect::Allow {
            return Err(usage(format!(
                "“{}” is protected: an agent always asks you for it, once per use (ADR 0032). Use --env {name}=ask (ask every time) or =deny",
                listing.name
            )));
        }
        out.push(EnvRule {
            spec: name.to_owned(),
            listing,
            effect,
        });
    }
    Ok(out)
}

/// Adds the rules of `envs` to `policy`. When `inject` had no rule, its
/// default goes in first as an explicit rule with no scope (ADR 0006 §2),
/// so the items no `--env` names keep it.
pub(crate) fn add_rules(policy: &mut Policy, envs: &[EnvRule]) {
    if envs.is_empty() {
        return;
    }
    if !policy
        .rules
        .iter()
        .any(|r| r.permission == Permission::Inject)
    {
        policy.rules.push(Rule::new(
            Permission::Inject,
            Permission::Inject.default_effect(),
        ));
    }
    policy.rules.extend(envs.iter().map(EnvRule::rule));
}

fn effect_text(effect: Effect, once: bool) -> &'static str {
    match (effect, once) {
        (Effect::Allow, _) => "allow",
        (Effect::Ask, true) => "ask once",
        (Effect::Ask, false) => "ask",
        (Effect::Deny, _) => "deny",
    }
}

/// A rule as the person wrote it, for the explanation.
fn describe(rule: &Rule) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !rule.scope.vaults.is_empty() || !rule.scope.projects.is_empty() {
        parts.push("on its projects".into());
    }
    if !rule.scope.tags.is_empty() {
        parts.push(format!("on tags {}", rule.scope.tags.join(", ")));
    }
    if !rule.scope.hours.is_empty() {
        parts.push("within hours".into());
    }
    let place = if parts.is_empty() {
        "on everything the grant shares".to_owned()
    } else {
        parts.join(", ")
    };
    format!(
        "`{} {}` {place}",
        klav_sdk::session::permission_name(rule.permission),
        effect_text(rule.effect, rule.once)
    )
}

/// The decision `policy` gives `inject` on environment `listing`.
fn decide(policy: &Policy, listing: &EnvironmentListing, now: u64) -> Decision {
    policy::evaluate(
        policy,
        &policy::Request {
            permission: Permission::Inject,
            vault: Target {
                id: listing.vault_id,
                name: listing.vault.clone(),
            },
            project: Target {
                id: listing.project_id,
                name: listing.project.clone(),
            },
            tags: Vec::new(),
            domain: None,
            item: Some(listing.id),
            method: None,
            path: None,
            mcp_tool: None,
            now,
        },
    )
}

/// Fails when a broader rule makes an environment stricter than its
/// `--env` (ADR 0006 §3, ADR 0032 §4.3): it would read as open and still
/// ask or deny. The error names that rule and proposes narrowing it by
/// items.
pub(crate) fn check_rules(policy: &Policy, envs: &[EnvRule], now: u64) -> CliResult<()> {
    for env in envs {
        let got = decide(policy, &env.listing, now);
        let wanted = env.wanted();
        if got.strictness() <= wanted.strictness() {
            continue;
        }
        let why = match got.reason {
            Reason::Rule(i) => policy
                .rules
                .get(i)
                .map(describe)
                .unwrap_or_else(|| "another rule".into()),
            Reason::PolicyExpired => "the grant's expiry".into(),
            _ => "the grant's other rules".into(),
        };
        return Err(usage(format!(
            "--env {}={} cannot work: {why} also covers “{}” and the most restrictive rule wins, so it would be `{}`. An environment cannot be more open than a broader rule. Narrow that rule by environment instead (for example --env <other>={} for each environment that needs it, without the general rule)",
            env.spec,
            effect_text(wanted.effect, wanted.once),
            env.listing.name,
            effect_text(got.effect, got.once),
            effect_text(got.effect, got.once),
        )));
    }
    Ok(())
}

/// The warnings of ADR 0032 §4.5: an environment in `allow` whose
/// references point to items the grant leaves in `deny`, outside its
/// projects, or protected — that run would fail or ask for approval.
pub(crate) async fn reference_warnings(
    ctx: &mut Ctx,
    policy: &Policy,
    envs: &[EnvRule],
    granted: &[ProjectSummary],
    now: u64,
) -> CliResult<Vec<String>> {
    let mut out = Vec::new();
    for env in envs.iter().filter(|e| e.effect == Effect::Allow) {
        let place = format!("{}/{}", env.listing.vault, env.listing.project);
        let Some(detail) = ctx
            .backend()
            .await?
            .environment(Some(&place), &env.listing.name)
            .await?
        else {
            continue;
        };
        for variable in &detail.variables {
            let VariableOrigin::Reference {
                reference,
                target,
                protected,
            } = &variable.origin
            else {
                continue;
            };
            let what = target.clone().unwrap_or_else(|| reference.clone());
            if *protected {
                out.push(format!(
                    "“{}” uses {what} ({}), which is protected: the agent's run of it asks you once each time",
                    env.listing.name, variable.name
                ));
                continue;
            }
            let Some((vault, project, item)) = ids_of(reference) else {
                continue;
            };
            let Some(summary) = granted.iter().find(|p| p.id == project) else {
                out.push(format!(
                    "“{}” uses {what} ({}), in a project this grant does not share: the agent's run of it would fail",
                    env.listing.name, variable.name
                ));
                continue;
            };
            let decision = policy::evaluate(
                policy,
                &policy::Request {
                    permission: Permission::Inject,
                    vault: Target {
                        id: vault,
                        name: summary.vault.clone(),
                    },
                    project: Target {
                        id: project,
                        name: summary.name.clone(),
                    },
                    tags: Vec::new(),
                    domain: None,
                    item: Some(item),
                    method: None,
                    path: None,
                    mcp_tool: None,
                    now,
                },
            );
            if decision.effect == Effect::Deny {
                out.push(format!(
                    "“{}” uses {what} ({}), which this grant leaves in deny: the agent's run of it would fail",
                    env.listing.name, variable.name
                ));
            }
        }
    }
    Ok(out)
}

/// The vault, project and item of a reference stored by IDs.
fn ids_of(reference: &str) -> Option<(VaultId, ProjectId, ItemId)> {
    let parsed = Reference::parse(reference).ok()?;
    match (parsed.vault, parsed.project, parsed.item) {
        (RefSelector::Id(v), RefSelector::Id(p), RefSelector::Id(i)) => Some((v, p, i)),
        _ => None,
    }
}

/// The `--env` flags of `args`, resolved against the vault.
pub(crate) async fn env_rules(ctx: &mut Ctx, args: &AgentApproveArgs) -> CliResult<Vec<EnvRule>> {
    if args.environments.is_empty() {
        return Ok(Vec::new());
    }
    let listings = ctx.backend().await?.environments(None).await?;
    resolve(&args.environments, &args.projects, &args.vaults, &listings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing(name: &str, protected: bool) -> EnvironmentListing {
        EnvironmentListing {
            id: ItemId::generate(),
            vault_id: VaultId::generate(),
            vault: "Work".into(),
            project_id: ProjectId::generate(),
            project: "acme-api".into(),
            name: name.into(),
            variables: 1,
            protected,
            updated_at: 0,
            author_agent_id: None,
        }
    }

    fn projects() -> Vec<String> {
        vec!["Work/acme-api".into()]
    }

    #[test]
    fn rules_are_scoped_by_item_and_keep_the_default_explicit() {
        let dev = listing("development", false);
        let staging = listing("staging", false);
        let prod = listing("production", true);
        let all = vec![dev.clone(), staging.clone(), prod.clone()];
        let envs = resolve(
            &[
                "development=allow".into(),
                "staging=ask".into(),
                "production=ask".into(),
            ],
            &projects(),
            &[],
            &all,
        )
        .unwrap();
        let mut policy = Policy::default();
        add_rules(&mut policy, &envs);
        // The default first, with no scope (ADR 0006 §2).
        assert_eq!(
            policy.rules[0],
            Rule::new(Permission::Inject, Effect::Allow)
        );
        assert_eq!(policy.rules.len(), 4);
        assert!(policy.rules[3].once, "a protected environment asks once");
        check_rules(&policy, &envs, 0).unwrap();
        assert_eq!(decide(&policy, &dev, 0).effect, Effect::Allow);
        let s = decide(&policy, &staging, 0);
        assert!(s.effect == Effect::Ask && !s.once);
        assert!(decide(&policy, &prod, 0).once);
        // Another item of the project keeps the default.
        let other = listing("login", false);
        let mut other = other;
        other.project_id = dev.project_id;
        assert_eq!(decide(&policy, &other, 0).effect, Effect::Allow);
        // The policy is one the person's client signs.
        policy.check_once().unwrap();
        policy.check_grantable().unwrap();
    }

    #[test]
    fn a_protected_environment_is_never_allow() {
        let prod = listing("production", true);
        let e = resolve(&["production=allow".into()], &projects(), &[], &[prod])
            .unwrap_err()
            .message()
            .unwrap_or_default();
        assert!(e.contains("is protected"), "{e}");
    }

    #[test]
    fn a_broader_rule_that_wins_is_explained() {
        let dev = listing("development", false);
        let envs = resolve(&["development=allow".into()], &projects(), &[], &[dev]).unwrap();
        let mut policy = Policy {
            rules: vec![Rule::new(Permission::Inject, Effect::Ask)],
            expires_at: None,
        };
        add_rules(&mut policy, &envs);
        let e = check_rules(&policy, &envs, 0)
            .unwrap_err()
            .message()
            .unwrap_or_default();
        assert!(
            e.contains("`inject ask` on everything the grant shares"),
            "{e}"
        );
        assert!(e.contains("Narrow that rule"), "{e}");
    }

    #[test]
    fn names_must_be_found_once_in_the_shared_projects() {
        let a = listing("development", false);
        let mut b = listing("development", false);
        b.project = "web".into();
        let both = vec![a, b];
        let e = resolve(
            &["development=allow".into()],
            &projects(),
            &["Work".into()],
            &both,
        )
        .unwrap_err()
        .message()
        .unwrap_or_default();
        assert!(e.contains("several projects"), "{e}");
        assert!(
            resolve(
                &["Work/web/development=deny".into()],
                &[],
                &["Work".into()],
                &both
            )
            .is_ok()
        );
        let e = resolve(&["qa=allow".into()], &projects(), &[], &both)
            .unwrap_err()
            .message()
            .unwrap_or_default();
        assert!(e.contains("no environment \"qa\""), "{e}");
        assert!(resolve(&["development=maybe".into()], &projects(), &[], &both).is_err());
    }
}
