//! The account's preferences (ADR 0032 §7, ADR 0036 §3): one system item of
//! kind `preferences` in the system project of the personal vault
//! ([`super::history::system_project_id`]), synced and encrypted like any
//! item. No grant includes the system project, so no agent reads or
//! changes it.
//!
//! Its details carry `preferences: {developer?, proxy?}` (spec §7.1). A key
//! that is absent takes its default, and a client writes only the keys a
//! person chose: without the item, «Development» is on (ADR 0032 §7) and
//! the account uses no credential proxy (ADR 0036 §3). Unknown keys are
//! rejected, like every section of an item: a later key comes with its own
//! ADR, and an older client then fails closed on the item.

use serde::{Deserialize, Serialize};

use super::item::ModelError;
use crate::ids::AgentId;

/// Title of the preferences item.
pub const PREFERENCES_TITLE: &str = "Preferences";

/// The preferences of the account.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preferences {
    /// The «Development» switch (ADR 0032 §7). Absent: on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub developer: Option<bool>,
    /// Which credential proxy the account uses (ADR 0036 §3). Absent:
    /// [`ProxyMode::None`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxySetting>,
}

/// `proxy.mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    /// No proxy: what is lost is in ADR 0036 §13.
    None,
    /// The person's own proxy, an agent of the account (`agent_id`).
    Own,
    /// The hosted, attested proxy (ADR 0036 §12). Reserved: it does not
    /// exist yet, so clients read it and treat it as unsupported, and never
    /// write it.
    Klav,
}

/// `proxy`: `{mode, agent_id?}`. `agent_id` is there exactly when the mode
/// is `own`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxySetting {
    /// The mode.
    pub mode: ProxyMode,
    /// The proxy's agent, with `own`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
}

impl ProxySetting {
    /// No proxy.
    pub const NONE: Self = Self {
        mode: ProxyMode::None,
        agent_id: None,
    };

    /// The person's own proxy, `agent`.
    pub fn own(agent: AgentId) -> Self {
        Self {
            mode: ProxyMode::Own,
            agent_id: Some(agent),
        }
    }

    /// Checks that `agent_id` comes with `own` and only with it.
    pub fn validate(&self) -> Result<(), ModelError> {
        match (self.mode, self.agent_id) {
            (ProxyMode::Own, Some(_)) | (ProxyMode::None | ProxyMode::Klav, None) => Ok(()),
            _ => Err(ModelError::InvalidText("proxy setting")),
        }
    }
}

impl Preferences {
    /// The proxy setting, with its default.
    pub fn proxy(&self) -> ProxySetting {
        self.proxy.unwrap_or(ProxySetting::NONE)
    }

    /// The «Development» switch, with its default (on).
    pub fn developer(&self) -> bool {
        self.developer.unwrap_or(true)
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        if let Some(proxy) = &self.proxy {
            proxy.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_keys_take_their_defaults() {
        let p: Preferences = serde_json::from_str("{}").unwrap();
        assert!(p.developer());
        assert_eq!(p.proxy(), ProxySetting::NONE);
        assert_eq!(serde_json::to_string(&p).unwrap(), "{}");
    }

    #[test]
    fn agent_id_comes_with_own_only() {
        let id = AgentId::generate();
        assert!(ProxySetting::own(id).validate().is_ok());
        assert!(ProxySetting::NONE.validate().is_ok());
        for bad in [
            ProxySetting {
                mode: ProxyMode::Own,
                agent_id: None,
            },
            ProxySetting {
                mode: ProxyMode::None,
                agent_id: Some(id),
            },
            ProxySetting {
                mode: ProxyMode::Klav,
                agent_id: Some(id),
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn unknown_keys_and_modes_are_rejected() {
        assert!(serde_json::from_str::<Preferences>(r#"{"theme":"dark"}"#).is_err());
        assert!(serde_json::from_str::<Preferences>(r#"{"proxy":{"mode":"hosted"}}"#).is_err());
        assert!(
            serde_json::from_str::<Preferences>(r#"{"proxy":{"mode":"none","url":"x"}}"#).is_err()
        );
        let klav: Preferences = serde_json::from_str(r#"{"proxy":{"mode":"klav"}}"#).unwrap();
        assert_eq!(klav.proxy().mode, ProxyMode::Klav);
    }
}
