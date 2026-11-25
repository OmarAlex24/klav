//! Item model and `klav://` references (design §3).

pub mod agent_labels;
pub mod environment;
pub mod history;
pub mod item;
pub mod meta;
pub mod passkey;
pub mod preferences;
pub mod record;
pub mod reference;

pub use environment::{
    Author, Environment, EnvironmentSummary, EnvironmentVersion, Variable, VariableSource,
    effective_protected, protected_environments, protected_set,
};
pub use item::{
    AttachmentMeta, Field, FieldKind, FieldValue, Item, ItemKind, ModelError, Overview, SealedItem,
    SecretValue, open_item, open_overview, seal_item, template,
};
pub use meta::{
    Meta, normalize_repo_url, open_project_meta, open_vault_meta, seal_project_meta,
    seal_vault_meta,
};
pub use passkey::{Passkey, PasskeyAccount, PasskeySummary};
pub use reference::{
    Catalog, Named, Reference, ReferenceError, ResolvedReference, Selector, resolve_field,
    resolve_variable,
};
