//! The account's preferences (ADR 0032 §7, ADR 0036 §3): the `preferences`
//! system item in the system project of the account's vaults
//! ([`klav_core::model::preferences`]).
//!
//! Reading fails closed: an item of a system project that this device has
//! but cannot open, or a preferences item an agent wrote, is an error,
//! never «no preferences» (which would read as «no proxy» and make the next
//! write create a second item). Two devices that created the item at once
//! leave two: both are read, and they must agree; writing sets the same
//! value in all of them.
//!
//! Nothing in a preferences item an agent wrote is used or kept: no reader
//! trusts its setting, and only the person's `klav proxy use`, after
//! presence, replaces it, with a new body that holds only the setting the
//! person chose and none of the agent's content
//! ([`crate::proxy_admin::PreparedProxyUse`]). Rewriting it still decrypts
//! the current version, as every item update does, and sync decrypts its
//! overview; neither carries anything over. The sandbox list shows the
//! chain's rows with a security flag instead of failing
//! ([`crate::sandboxes::SecurityFlag`]); every other reader still fails.

use klav_core::ids::{AccountId, AgentId, ItemId, VaultId};
use klav_core::model::item::{Item, ItemKind};
use klav_core::model::preferences::{PREFERENCES_TITLE, Preferences, ProxyMode, ProxySetting};

use crate::error::{ClientError, ClientResult};
use crate::sandboxes::SecurityFlag;
use crate::session::{ItemLocation, Unlocked};

/// The account's preferences items, as found without using one an agent
/// wrote.
pub(crate) enum PreferencesRead {
    /// Every preferences item is the person's: what they say.
    Read(Preferences),
    /// An agent wrote these items (oldest ID first). Nothing of theirs is
    /// used: no proxy is trusted until the person sets it again.
    ByAgent(Vec<(ItemLocation, AgentId)>),
}

/// What [`Unlocked::scan_preferences`] found.
struct Scan {
    /// The person's items, opened.
    person: Vec<(ItemLocation, Item)>,
    /// The items an agent wrote, by their author only: nothing in them is used.
    by_agent: Vec<(ItemLocation, AgentId)>,
    /// An item of a system project this device has but cannot open.
    unopened: Option<ItemId>,
}

impl Scan {
    /// An item this device cannot open may hold the preferences: no
    /// reader or writer takes the rest as all there is.
    fn complete(&self) -> ClientResult<()> {
        match self.unopened {
            Some(id) => Err(ClientError::Corrupt(format!(
                "item {id} of Klav's own project does not open on this device, and it may \
                 hold the account's preferences; update Klav, or sync again"
            ))),
            None => Ok(()),
        }
    }
}

impl Unlocked {
    /// The account's preferences, with the defaults of what no item sets.
    pub fn preferences(&self) -> ClientResult<Preferences> {
        match self.read_preferences()? {
            PreferencesRead::Read(p) => Ok(p),
            PreferencesRead::ByAgent(items) => Err(by_agent_error(&items)),
        }
    }

    /// The preferences, or the items an agent wrote, which are an error for
    /// every reader but the sandbox list and `klav proxy use`.
    pub(crate) fn read_preferences(&self) -> ClientResult<PreferencesRead> {
        let scan = self.scan_preferences()?;
        // An agent's item first: it is a security problem whatever else
        // the scan found.
        if !scan.by_agent.is_empty() {
            return Ok(PreferencesRead::ByAgent(scan.by_agent));
        }
        scan.complete()?;
        let mut found: Option<Preferences> = None;
        for (_, item) in &scan.person {
            let here = item.preferences().cloned().unwrap_or_default();
            match &found {
                None => found = Some(here),
                Some(first) if first.proxy() != here.proxy() => {
                    return Err(ClientError::Invalid(
                        "the account has two preferences items that disagree on the credential \
                         proxy; set it again with `klav proxy use`"
                            .into(),
                    ));
                }
                Some(_) => {}
            }
        }
        Ok(PreferencesRead::Read(found.unwrap_or_default()))
    }

    /// Sets which credential proxy the account uses, in every preferences
    /// item (creating one when there is none). Other keys stay as each
    /// item has them. `klav` mode is never written: it does not exist yet.
    /// A preferences item an agent wrote fails it, as reading does.
    pub async fn set_proxy_setting(&mut self, setting: ProxySetting) -> ClientResult<()> {
        self.set_proxy_setting_replacing(setting, &[]).await
    }

    /// [`Self::set_proxy_setting`], replacing whole the items an agent
    /// wrote that are in `replace` (those `klav proxy use` showed before
    /// presence): each gets a new body with only `setting`, and the
    /// person's authorship. One an agent wrote that is not in `replace`
    /// fails it, before anything is written.
    pub(crate) async fn set_proxy_setting_replacing(
        &mut self,
        setting: ProxySetting,
        replace: &[ItemLocation],
    ) -> ClientResult<()> {
        setting
            .validate()
            .map_err(|e| ClientError::Invalid(e.to_string()))?;
        if setting.mode == ProxyMode::Klav {
            return Err(ClientError::Invalid(
                "Klav's hosted proxy does not exist yet (ADR 0036 §12)".into(),
            ));
        }
        // Another device may write it meanwhile: `update_item` syncs on a
        // conflict, so one retry starts from theirs.
        let mut attempt = 0;
        loop {
            match self.write_proxy_setting(setting, replace).await {
                Err(ClientError::Conflict(_)) if attempt == 0 => attempt += 1,
                other => return other,
            }
        }
    }

    async fn write_proxy_setting(
        &mut self,
        setting: ProxySetting,
        replace: &[ItemLocation],
    ) -> ClientResult<()> {
        let scan = self.scan_preferences()?;
        if let Some((_, agent)) = scan.by_agent.iter().find(|(l, _)| !replace.contains(l)) {
            return Err(ClientError::Security(
                SecurityFlag::PreferencesByAgent { agent_id: *agent }.message(),
            ));
        }
        scan.complete()?;
        if scan.person.is_empty() && scan.by_agent.is_empty() {
            let vault = self.default_vault()?;
            self.require_owned(vault)?;
            let project = self.ensure_system_project(vault).await?;
            let mut item = Item::new(ItemKind::Preferences, PREFERENCES_TITLE)?;
            item.set_preferences(Some(Preferences {
                developer: None,
                proxy: Some(setting),
            }))?;
            self.add_item(vault, project, &item).await?;
            return Ok(());
        }
        for (loc, item) in scan.person {
            let mut prefs = item.preferences().cloned().unwrap_or_default();
            if prefs.proxy == Some(setting) {
                continue;
            }
            prefs.proxy = Some(setting);
            let mut changed = item.clone();
            changed.set_preferences(Some(prefs))?;
            self.update_item(loc, &changed).await?;
        }
        // Always written, also when the agent's body may hold the same
        // setting: what counts is that the person wrote it.
        for (loc, _) in scan.by_agent {
            self.update_item(loc, &fresh_preferences(loc.item, setting)?)
                .await?;
        }
        Ok(())
    }

    /// Every live preferences item of the account's own vaults: the
    /// person's opened, an agent's only located, and the first item of a
    /// system project this device cannot open.
    fn scan_preferences(&self) -> ClientResult<Scan> {
        let account = self.account.account_id;
        let mut scan = Scan {
            person: Vec::new(),
            by_agent: Vec::new(),
            unopened: None,
        };
        for vault in self.owned_vaults(account) {
            if scan.unopened.is_none() {
                scan.unopened = self.unopened_system_items(vault).first().copied();
            }
            for loc in self.system_items(vault, ItemKind::Preferences) {
                match self.item_summary(loc)?.author_agent_id {
                    Some(agent) => scan.by_agent.push((loc, agent)),
                    None => scan.person.push((loc, self.open_item(loc)?)),
                }
            }
        }
        Ok(scan)
    }

    /// The vaults this account owns (a shared vault's owner could plant a
    /// preferences item there).
    fn owned_vaults(&self, account: AccountId) -> Vec<VaultId> {
        let mut vaults: Vec<VaultId> = self
            .vaults
            .iter()
            .filter(|(_, v)| v.owner == account && !v.deleted)
            .map(|(id, _)| *id)
            .collect();
        vaults.sort_by_key(ToString::to_string);
        vaults
    }

    fn require_owned(&self, vault: VaultId) -> ClientResult<()> {
        match self.vaults.get(&vault) {
            Some(v) if v.owner == self.account.account_id => Ok(()),
            _ => Err(ClientError::Invalid(
                "the preferences live in a vault of this account".into(),
            )),
        }
    }
}

/// The error every reader but the list gives for preferences an agent
/// wrote: it names the first one's agent.
pub(crate) fn by_agent_error(items: &[(ItemLocation, AgentId)]) -> ClientError {
    match items.first() {
        Some((_, agent)) => {
            ClientError::Security(SecurityFlag::PreferencesByAgent { agent_id: *agent }.message())
        }
        None => ClientError::Security("the account's preferences were written by an agent".into()),
    }
}

/// A preferences item `id` with only `setting`: none of the agent's body
/// (its developer switch, title, fields or notes) carries over.
fn fresh_preferences(id: ItemId, setting: ProxySetting) -> ClientResult<Item> {
    let mut fresh = Item::new(ItemKind::Preferences, PREFERENCES_TITLE)?;
    fresh.set_preferences(Some(Preferences {
        developer: None,
        proxy: Some(setting),
    }))?;
    // `Item::new` draws a new ID; the item written keeps its own. Built
    // from sections only this function filled.
    let (overview, details) = fresh.encode_sections();
    Ok(Item::decode_sections(id, &overview, &details)?)
}
