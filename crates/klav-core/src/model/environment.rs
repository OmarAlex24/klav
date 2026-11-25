//! Environments per repository (ADR 0032 §1, §3 and §3.1).
//!
//! An `environment` item is one set of variables for one project and one
//! environment name (`development`, `staging`, `production`). Each variable
//! carries either its own secret **value** or a `klav://` **reference** to a
//! field of another item that is not an environment. Its overview carries
//! `environment: {protected, variables: [names…]}`; its details carry the
//! variables themselves (spec §7.1).
//!
//! This module also holds the two pure functions every client shares for
//! production (ADR 0032 §3 and §3.1):
//!
//! * [`effective_protected`]: whether an environment is protected, from the
//!   latest version the person wrote, failing closed when only agents wrote
//!   it;
//! * [`protected_set`]: the items that references from protected
//!   environments point to, computed only from the person's versions.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::item::{ItemKind, ModelError, SecretValue, validate_field_name};
use super::reference::{Reference, Selector};
use crate::ids::ItemId;

/// Longest variable name, in bytes.
pub const MAX_VARIABLE_NAME_LEN: usize = 128;
/// Most variables in one environment.
pub const MAX_VARIABLES: usize = 512;

/// Checks an environment name (the item's title): `[a-z0-9][a-z0-9_-]{0,63}`
/// and not shaped like an ID, so `--env` and `klav://` write it without
/// quotes (ADR 0032 §1). The same grammar as a field name.
pub fn validate_environment_name(name: &str) -> Result<(), ModelError> {
    validate_field_name(name).map_err(|_| ModelError::InvalidTitle)
}

/// Checks a variable name: `[A-Za-z_][A-Za-z0-9_]{0,127}`. Names are
/// case-sensitive: `API_KEY` and `api_key` are two variables.
pub fn validate_variable_name(name: &str) -> Result<(), ModelError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_VARIABLE_NAME_LEN
        && name
            .bytes()
            .enumerate()
            .all(|(i, b)| b.is_ascii_alphabetic() || b == b'_' || (i > 0 && b.is_ascii_digit()));
    if valid {
        Ok(())
    } else {
        Err(ModelError::InvalidVariable(name.to_owned()))
    }
}

/// Whether an environment name turns `protected` on by itself:
/// `production` or `prod`, ignoring ASCII case (ADR 0032 §3).
pub fn is_production_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("production") || name.eq_ignore_ascii_case("prod")
}

/// Where a variable's value comes from. Not `Debug`: a value is a secret.
#[derive(Clone, PartialEq, Eq)]
pub enum VariableSource {
    /// Its own secret value. Never in the overview.
    Value(SecretValue),
    /// A field of another item, by ID (`klav://<vault>/<project>/<item>/<field>`
    /// with four UUIDs). It resolves with the permissions of the item it
    /// points to.
    Ref(Reference),
}

/// One variable of an environment.
#[derive(Clone, PartialEq, Eq)]
pub struct Variable {
    name: String,
    source: VariableSource,
}

/// A reference as an environment stores it: four IDs, so a rename never
/// breaks it (ADR 0032 §1). The field segment is a field ID: a variable has
/// no ID, so a stored reference never names another environment's
/// variable.
fn check_stored_reference(name: &str, reference: &Reference) -> Result<(), ModelError> {
    let by_id = matches!(reference.vault, Selector::Id(_))
        && matches!(reference.project, Selector::Id(_))
        && matches!(reference.item, Selector::Id(_))
        && matches!(reference.field, Selector::Id(_));
    if by_id {
        Ok(())
    } else {
        Err(ModelError::InvalidVariable(name.to_owned()))
    }
}

impl Variable {
    /// A variable with its own value.
    pub fn with_value(name: &str, value: &str) -> Result<Self, ModelError> {
        validate_variable_name(name)?;
        Ok(Self {
            name: name.to_owned(),
            source: VariableSource::Value(SecretValue::new(value)),
        })
    }

    /// A variable that points to a field of another item, by ID.
    pub fn with_reference(name: &str, reference: Reference) -> Result<Self, ModelError> {
        validate_variable_name(name)?;
        check_stored_reference(name, &reference)?;
        Ok(Self {
            name: name.to_owned(),
            source: VariableSource::Ref(reference),
        })
    }

    /// Its name (case-sensitive).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Its value or its reference.
    pub fn source(&self) -> &VariableSource {
        &self.source
    }

    /// The item its reference points to, if it is a reference.
    pub fn target_item(&self) -> Option<ItemId> {
        match &self.source {
            VariableSource::Ref(Reference {
                item: Selector::Id(id),
                ..
            }) => Some(*id),
            _ => None,
        }
    }
}

/// What the overview says about an environment: no values, no references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentSummary {
    /// The `protected` flag of this version (ADR 0032 §3). Which flag counts
    /// is decided by [`effective_protected`], not by this field alone.
    pub protected: bool,
    /// The variable names, in the order of the details.
    pub variables: Vec<String>,
}

/// What an `environment` item holds.
#[derive(Clone, PartialEq, Eq)]
pub struct Environment {
    protected: bool,
    variables: Vec<Variable>,
}

impl Environment {
    /// An empty environment.
    pub fn new(protected: bool) -> Self {
        Self {
            protected,
            variables: Vec::new(),
        }
    }

    /// The `protected` flag of this version.
    pub fn protected(&self) -> bool {
        self.protected
    }

    /// Turns the flag on or off. Turning it off asks for presence in the
    /// person's apps (ADR 0032 §3); that check belongs to the caller.
    pub fn set_protected(&mut self, protected: bool) {
        self.protected = protected;
    }

    /// The variables, in order.
    pub fn variables(&self) -> &[Variable] {
        &self.variables
    }

    /// The variable called exactly `name` (case-sensitive).
    pub fn variable(&self, name: &str) -> Option<&Variable> {
        self.variables.iter().find(|v| v.name == name)
    }

    /// Adds `variable`, or replaces the one with the same name in place.
    pub fn set(&mut self, variable: Variable) -> Result<(), ModelError> {
        if let Some(slot) = self.variables.iter_mut().find(|v| v.name == variable.name) {
            *slot = variable;
            return Ok(());
        }
        if self.variables.len() >= MAX_VARIABLES {
            return Err(ModelError::InvalidText("too many variables"));
        }
        self.variables.push(variable);
        Ok(())
    }

    /// Adds `variable`; its name must be new.
    pub fn add(&mut self, variable: Variable) -> Result<(), ModelError> {
        if self.variable(&variable.name).is_some() {
            return Err(ModelError::DuplicateVariable(variable.name));
        }
        self.set(variable)
    }

    /// Removes the variable called exactly `name`.
    pub fn remove(&mut self, name: &str) -> Option<Variable> {
        let index = self.variables.iter().position(|v| v.name == name)?;
        Some(self.variables.remove(index))
    }

    /// What the overview carries.
    pub fn summary(&self) -> EnvironmentSummary {
        EnvironmentSummary {
            protected: self.protected,
            variables: self.variables.iter().map(|v| v.name.clone()).collect(),
        }
    }

    /// The items its references point to, without repeats, in order.
    pub fn reference_targets(&self) -> Vec<ItemId> {
        let mut out = Vec::new();
        for id in self.variables.iter().filter_map(Variable::target_item) {
            if !out.contains(&id) {
                out.push(id);
            }
        }
        out
    }

    /// Checks that no reference points to an environment (ADR 0032 §1: no
    /// chains and no cycles), this one included. `kind_of` gives the kind
    /// of an item the caller can see; an item it cannot see is left to
    /// resolution, which fails if it is missing.
    pub fn check_references(
        &self,
        own: ItemId,
        kind_of: impl Fn(ItemId) -> Option<ItemKind>,
    ) -> Result<(), ModelError> {
        for variable in &self.variables {
            if let Some(target) = variable.target_item()
                && (target == own || kind_of(target) == Some(ItemKind::Environment))
            {
                return Err(ModelError::ReferenceToEnvironment(variable.name.clone()));
            }
        }
        Ok(())
    }
}

/// A variable in the details JSON: `{name, value}` or `{name, ref}`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawVariable {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    reference: Option<String>,
}

impl Drop for RawVariable {
    fn drop(&mut self) {
        if let Some(value) = self.value.as_mut() {
            zeroize::Zeroize::zeroize(value);
        }
    }
}

impl Environment {
    /// The details' `variables`.
    pub(crate) fn to_raw(&self) -> Vec<RawVariable> {
        self.variables
            .iter()
            .map(|v| match &v.source {
                VariableSource::Value(value) => RawVariable {
                    name: v.name.clone(),
                    value: Some(value.expose().to_owned()),
                    reference: None,
                },
                VariableSource::Ref(reference) => RawVariable {
                    name: v.name.clone(),
                    value: None,
                    reference: Some(reference.to_string()),
                },
            })
            .collect()
    }

    /// Rebuilds an environment from the overview's flag and the details'
    /// variables. Names are unique; each variable has a value or a
    /// reference, never both.
    pub(crate) fn from_raw(protected: bool, raw: &[RawVariable]) -> Result<Self, ModelError> {
        if raw.len() > MAX_VARIABLES {
            return Err(ModelError::InvalidText("too many variables"));
        }
        let mut environment = Self::new(protected);
        for r in raw {
            let variable = match (&r.value, &r.reference) {
                (Some(value), None) => Variable::with_value(&r.name, value)?,
                (None, Some(text)) => {
                    let reference = Reference::parse(text)
                        .map_err(|_| ModelError::InvalidVariable(r.name.clone()))?;
                    Variable::with_reference(&r.name, reference)?
                }
                _ => return Err(ModelError::InvalidVariable(r.name.clone())),
            };
            environment.add(variable)?;
        }
        Ok(environment)
    }
}

// ------------------------------------------------- production (§3, §3.1) --

/// Who wrote a version (ADR 0030 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Author {
    /// One of the person's devices.
    Person,
    /// An agent.
    Agent,
}

/// One version of an environment, as the person's client has it.
#[derive(Clone, Copy)]
pub struct EnvironmentVersion<'a> {
    /// The environment item.
    pub item: ItemId,
    /// Its version number.
    pub version: u64,
    /// Who wrote it.
    pub author: Author,
    /// Its title (the environment's name) in that version.
    pub title: &'a str,
    /// What it holds in that version.
    pub environment: &'a Environment,
}

/// The latest version the person wrote, per environment, and whether each
/// environment has one.
fn by_item<'v, 'a>(
    versions: &'v [EnvironmentVersion<'a>],
) -> BTreeMap<
    ItemId,
    (
        Option<&'v EnvironmentVersion<'a>>,
        Vec<&'v EnvironmentVersion<'a>>,
    ),
> {
    let mut out: BTreeMap<
        ItemId,
        (
            Option<&EnvironmentVersion<'a>>,
            Vec<&EnvironmentVersion<'a>>,
        ),
    > = BTreeMap::new();
    for v in versions {
        let entry = out.entry(v.item).or_default();
        entry.1.push(v);
        if v.author == Author::Person && entry.0.is_none_or(|p| v.version > p.version) {
            entry.0 = Some(v);
        }
    }
    out
}

/// Whether one environment is protected (ADR 0032 §3), from `versions`, the
/// versions of that environment the client has (any order).
///
/// * The flag that counts is the one of the **latest version the person
///   wrote**: an agent with `update` cannot turn it off.
/// * With no version by the person (an agent created it), it fails closed:
///   protected if any version has the flag on or is called `production` or
///   `prod`.
/// * With no version at all, it is protected: the caller does not know.
pub fn effective_protected(versions: &[EnvironmentVersion<'_>]) -> bool {
    let person = versions
        .iter()
        .filter(|v| v.author == Author::Person)
        .max_by_key(|v| v.version);
    match person {
        Some(p) => p.environment.protected,
        None => {
            versions.is_empty()
                || versions
                    .iter()
                    .any(|v| v.environment.protected || is_production_name(v.title))
        }
    }
}

/// The environments of `versions` that are protected ([`effective_protected`]
/// per item).
pub fn protected_environments(versions: &[EnvironmentVersion<'_>]) -> BTreeSet<ItemId> {
    by_item(versions)
        .into_iter()
        .filter(|(_, (_, all))| {
            let all: Vec<EnvironmentVersion<'_>> = all.iter().map(|v| **v).collect();
            effective_protected(&all)
        })
        .map(|(item, _)| item)
        .collect()
}

/// The protected set (ADR 0032 §3.1): the items that references from
/// protected environments point to, computed only from the person's
/// versions.
///
/// For each environment, its latest version written by the person is
/// taken. If that version has `protected` on, the target item of each of
/// its references goes in the set. Agent versions never shrink it (they are
/// not looked at), and an environment only agents wrote adds nothing: its
/// references protect no other item. A reference counts the same wherever
/// it points, in any project or vault.
pub fn protected_set(versions: &[EnvironmentVersion<'_>]) -> BTreeSet<ItemId> {
    let mut set = BTreeSet::new();
    for (person, _) in by_item(versions).into_values() {
        if let Some(p) = person
            && p.environment.protected
        {
            set.extend(p.environment.reference_targets());
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{FieldId, ProjectId, VaultId};

    static_assertions::assert_not_impl_any!(Variable: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(VariableSource: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(Environment: std::fmt::Debug, std::fmt::Display);

    fn reference_to(item: ItemId) -> Reference {
        Reference {
            vault: Selector::Id(VaultId::generate()),
            project: Selector::Id(ProjectId::generate()),
            item: Selector::Id(item),
            field: Selector::Id(FieldId::generate()),
        }
    }

    #[test]
    fn names() {
        for good in ["API_KEY", "_x", "a", "DATABASE_URL2", &"A".repeat(128)] {
            assert!(validate_variable_name(good).is_ok(), "{good}");
        }
        for bad in ["", "1A", "A-B", "A B", "Ñ", &"A".repeat(129)] {
            assert!(validate_variable_name(bad).is_err(), "{bad}");
        }
        for good in ["production", "dev", "staging-eu", "a_1"] {
            assert!(validate_environment_name(good).is_ok(), "{good}");
        }
        for bad in [
            "Production",
            "-x",
            "a b",
            "",
            "6f3e2c1a-8b7d-4e5f-9a0b-1c2d3e4f5a6b",
        ] {
            assert!(validate_environment_name(bad).is_err(), "{bad}");
        }
        assert!(is_production_name("PROD") && is_production_name("Production"));
        assert!(!is_production_name("production-eu"));
    }

    #[test]
    fn variables_are_unique_and_case_sensitive() {
        let mut env = Environment::new(false);
        env.add(Variable::with_value("API_KEY", "a").unwrap())
            .unwrap();
        env.add(Variable::with_value("api_key", "b").unwrap())
            .unwrap();
        assert_eq!(
            env.add(Variable::with_value("API_KEY", "c").unwrap()).err(),
            Some(ModelError::DuplicateVariable("API_KEY".into()))
        );
        env.set(Variable::with_value("API_KEY", "c").unwrap())
            .unwrap();
        assert_eq!(env.summary().variables, ["API_KEY", "api_key"]);
        assert!(
            matches!(env.variable("API_KEY").unwrap().source(), VariableSource::Value(v) if v.expose() == "c")
        );
        assert!(env.remove("api_key").is_some() && env.variable("api_key").is_none());
    }

    #[test]
    fn references_are_stored_by_id_and_never_to_an_environment() {
        let by_name = Reference::parse("klav://Trabajo/acme/Stripe/api_key").unwrap();
        assert!(Variable::with_reference("STRIPE", by_name).is_err());
        let own = ItemId::generate();
        let stripe = ItemId::generate();
        let staging = ItemId::generate();
        let mut env = Environment::new(true);
        env.add(Variable::with_reference("STRIPE", reference_to(stripe)).unwrap())
            .unwrap();
        let kinds = |id: ItemId| {
            if id == staging {
                Some(ItemKind::Environment)
            } else {
                Some(ItemKind::ApiKey)
            }
        };
        assert!(env.check_references(own, kinds).is_ok());
        env.add(Variable::with_reference("OTHER", reference_to(staging)).unwrap())
            .unwrap();
        assert_eq!(
            env.check_references(own, kinds).err(),
            Some(ModelError::ReferenceToEnvironment("OTHER".into()))
        );
        let mut selfish = Environment::new(false);
        selfish
            .add(Variable::with_reference("ME", reference_to(own)).unwrap())
            .unwrap();
        assert!(selfish.check_references(own, |_| None).is_err());
    }

    #[test]
    fn protection_comes_from_the_person() {
        let prod = ItemId::generate();
        let stripe = ItemId::generate();
        let db = ItemId::generate();
        let mut person = Environment::new(true);
        person
            .add(Variable::with_reference("STRIPE", reference_to(stripe)).unwrap())
            .unwrap();
        // The agent turns it off and points elsewhere: it does not count.
        let mut agent = Environment::new(false);
        agent
            .add(Variable::with_reference("DB", reference_to(db)).unwrap())
            .unwrap();
        let versions = [
            EnvironmentVersion {
                item: prod,
                version: 1,
                author: Author::Person,
                title: "production",
                environment: &person,
            },
            EnvironmentVersion {
                item: prod,
                version: 2,
                author: Author::Agent,
                title: "production",
                environment: &agent,
            },
        ];
        assert!(effective_protected(&versions));
        assert_eq!(protected_set(&versions), BTreeSet::from([stripe]));
        // Agent-only: protected by its name, but protects nothing else.
        let only_agent = [EnvironmentVersion {
            item: prod,
            version: 1,
            author: Author::Agent,
            title: "prod",
            environment: &agent,
        }];
        assert!(effective_protected(&only_agent));
        assert!(protected_set(&only_agent).is_empty());
        assert!(effective_protected(&[]));
    }
}
