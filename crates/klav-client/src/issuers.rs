//! `klav proxy issuer add|remove` (ADR 0036 §4, E6.2): the person lets an
//! agent start sandboxes through the account's credential proxy, and with
//! what. Two grants change together, each signed by the account: the
//! proxy's (`issuers`, what each issuer may ask for) and the issuer's
//! (`sandbox`, which proxy it talks to and where). Both are `v: 3`.
//!
//! Like `klav proxy grant`, the change is prepared first (every check, the
//! names and limits to show), then `klavd` asks for presence with what it
//! is about to sign, then it is committed. Nothing here touches an item key
//! or a value.

use klav_core::crypto::agent::pairing_code;
use klav_core::crypto::identity::PublicIdentity;
use klav_core::ids::AgentId;
use klav_core::policy::{Effect, Permission, Policy, Rule};
use klav_proto::Blob;
use klav_proto::agent::{
    AgentStatus, DEFAULT_LIVE_SANDBOXES, DEFAULT_SANDBOX_TTL_SECS, GRANT_PAYLOAD_VERSION,
    GRANT_PAYLOAD_VERSION_SANDBOXES, GrantPayload, IssuerGrant, MAX_LIVE_SANDBOXES,
    MAX_SANDBOX_TTL_SECS, MIN_SANDBOX_TTL_SECS, SandboxIssuer, SandboxProxy,
};
use serde::{Deserialize, Serialize};

use crate::agents::AgentView;
use crate::error::{ClientError, ClientResult};
use crate::proxy_admin::PairingCheck;
use crate::session::Unlocked;

/// What devices too old for sandbox issuers lose once the account signs
/// its first `v: 3` grant (`klav proxy issuer add`), shown before it and
/// in the refusal without `--every-device-is-updated`.
pub const OLDER_CLIENTS_ISSUERS: &str = "The first sandbox issuer changes the credential proxy's grant to a format older versions cannot read: a klav-proxy older than this one stops serving every credential until it is updated; an agent made an issuer gets a grant in that format too, so with an older Klav it can no longer read its own grant and its `run`, `inject` and MCP stop; devices with a Klav from before sandboxes can no longer list agents (CLI, klavd, and the request lists of the iPhone and Mac apps), and their `klav log verify` fails on the new grant. This lasts: `issuer remove` and revoking the agents do not undo it, since the issuer's grant keeps its new format, the server keeps revoked agents' grants and the log keeps every grant. Devices do not report their Klav version, so nothing can check this for you: update klav-proxy and Klav on every device (apps, CLI and klavd) first";

/// Most profiles one issuer may be given: the confirmation shows each.
/// The format refuses more (`GrantPayload::check_format`).
pub const MAX_ISSUER_PROFILES: usize = klav_proto::agent::MAX_ISSUER_PROFILES;

/// What the person asks for in `klav proxy issuer add`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerSpec {
    /// Profiles of the proxy its sandboxes may use.
    pub profiles: Vec<String>,
    /// Where a sandbox reaches the proxy: `tls://host:port` (spec §13.10).
    pub url: String,
    /// Longest TTL it may give a sandbox, in seconds (default 8 h).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl_secs: Option<u64>,
    /// Most of its sandboxes alive at once (default 3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_live: Option<u32>,
    /// Put `inject` in `ask` in the issuer's grant (ADR 0036 E6.2, Q-D).
    #[serde(default)]
    pub inject_ask: bool,
}

/// What an issuer change does, to show before presence. Names, limits,
/// the proxy's address and the issuer's words: never a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerChangeView {
    /// The issuer.
    pub issuer_id: AgentId,
    /// Its name.
    pub issuer: String,
    /// The issuer is pending: this approves it, with its words.
    pub pending: bool,
    /// Its 6 pairing words, from the key this change signs for.
    pub pairing_code: String,
    /// The credential proxy.
    pub proxy_id: AgentId,
    /// Its name.
    pub proxy: String,
    /// `true` for `issuer remove`.
    pub remove: bool,
    /// The proxy's address the issuer's grant names (empty on remove).
    #[serde(default)]
    pub url: String,
    /// Profiles its sandboxes may use.
    #[serde(default)]
    pub profiles: Vec<String>,
    /// Longest TTL, in seconds.
    #[serde(default)]
    pub max_ttl_secs: u64,
    /// Most live sandboxes.
    #[serde(default)]
    pub max_live: u32,
    /// The issuer's policy lets it `inject` somewhere without asking.
    #[serde(default)]
    pub inject_allowed: bool,
    /// This change puts `inject` in `ask` for it.
    #[serde(default)]
    pub inject_ask: bool,
    /// The account's first `v: 3` grant: older devices break.
    #[serde(default)]
    pub first_on_account: bool,
    /// The proxy's grant version this change is built on.
    pub proxy_base_version: u64,
    /// The issuer's grant version this change is built on (0: none).
    pub issuer_base_version: u64,
    /// Which grants change: the issuer's, the proxy's.
    pub issuer_changes: bool,
    /// See `issuer_changes`.
    pub proxy_changes: bool,
    /// Warnings to show before presence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// A checked issuer change, ready to sign.
pub struct PreparedIssuerChange {
    view: IssuerChangeView,
    issuer_public: PublicIdentity,
    /// The issuer's grant as it is (`None`: pending, no grant).
    issuer_current: Option<GrantPayload>,
    /// The issuer's grant to sign, when it changes.
    issuer_next: Option<IssuerNext>,
    proxy_public: PublicIdentity,
    /// The proxy's grant to sign, when it changes (opened, with the new
    /// `issuers`).
    proxy_next: Option<GrantPayload>,
}

/// The issuer's new grant: a change of the one it has, or its first.
enum IssuerNext {
    Change(GrantPayload),
    First {
        policy: Policy,
        sandbox: IssuerGrant,
    },
}

impl PreparedIssuerChange {
    /// What it does.
    #[must_use]
    pub fn view(&self) -> &IssuerChangeView {
        &self.view
    }

    /// Refuses the account's first `v: 3` grant unless every device was
    /// updated (`--every-device-is-updated`), saying what breaks.
    pub fn require_updated_devices(&self, every_device_updated: bool) -> ClientResult<()> {
        if self.view.first_on_account && !every_device_updated {
            return Err(ClientError::Invalid(format!(
                "this is the account's first sandbox issuer. {OLDER_CLIENTS_ISSUERS}, then run it again with --every-device-is-updated"
            )));
        }
        Ok(())
    }
}

/// What an issuer change did. Both grants or neither is the goal; the
/// order makes a half-done change harmless (the proxy refuses an issuer
/// it does not list), and running the same command again finishes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerReport {
    /// The issuer, as it is now.
    pub issuer: AgentView,
    /// The issuer's grant was uploaded (or had nothing to change).
    pub issuer_done: bool,
    /// The proxy's grant was uploaded (or had nothing to change).
    pub proxy_done: bool,
    /// What stopped it, if it stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<String>,
}

impl IssuerReport {
    /// Whether both grants are as the person asked.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.issuer_done && self.proxy_done && self.failed.is_none()
    }
}

/// The issuers of re-signs that a change of the proxy setting did.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IssuerResign {
    /// Issuers whose grant now names no proxy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub done: Vec<String>,
    /// Issuers whose grant could not be re-signed (`name: why`). Running
    /// `klav proxy use` again finishes them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<String>,
}

/// Whether `policy` lets the agent `inject` somewhere without asking: no
/// `inject` rule (the default is `allow`, design §5.2) or an `allow` one.
#[must_use]
pub fn inject_allowed(policy: &Policy) -> bool {
    let rules: Vec<&Rule> = policy
        .rules
        .iter()
        .filter(|r| r.permission == Permission::Inject)
        .collect();
    // A stricter rule that matches everything wins over every `allow`.
    if rules
        .iter()
        .any(|r| r.effect != Effect::Allow && covers_all(r))
    {
        return false;
    }
    rules.is_empty() || rules.iter().any(|r| r.effect == Effect::Allow)
}

/// A rule with no scope that never expires: it matches every request.
fn covers_all(rule: &Rule) -> bool {
    rule.scope == klav_core::policy::Scope::default() && rule.expires_at.is_none()
}

/// `policy` with every `inject` that is not a `deny` asking first: an
/// `ask` rule with no scope, which wins over any `allow` (the stricter
/// matching rule wins). The `deny` rules stay.
fn inject_asks(mut policy: Policy) -> Policy {
    let asks = policy
        .rules
        .iter()
        .any(|r| r.permission == Permission::Inject && r.effect != Effect::Allow && covers_all(r));
    if !asks {
        policy
            .rules
            .push(Rule::new(Permission::Inject, Effect::Ask));
    }
    policy
}

impl Unlocked {
    /// Checks `klav proxy issuer add <agent>`: the account's proxy, the
    /// agent (pending or active, never the proxy, never a holder of
    /// credentials), the profiles (the proxy's own) and the limits. With
    /// a pending agent this approves it with no projects: an issuer holds
    /// no keys (ADR 0036 §4).
    pub async fn prepare_issuer_add(
        &mut self,
        agent: &str,
        spec: &IssuerSpec,
        check: PairingCheck<'_>,
    ) -> ClientResult<PreparedIssuerChange> {
        let proxy = self.current_proxy().await?;
        let Some(proxy_payload) = proxy.payload.clone() else {
            return Err(ClientError::Invalid(format!(
                "the proxy {:?} holds no credentials yet: grant it one with `klav proxy grant` first",
                proxy.name
            )));
        };
        let issuer = self.agent(agent).await?;
        let (issuer_public, issuer_current, pending) =
            self.issuer_candidate(&issuer, proxy.id).await?;
        if pending {
            match check {
                PairingCheck::Typed(Some(w))
                    if klav_core::crypto::agent::pairing_code_matches(&issuer_public, w) => {}
                PairingCheck::Typed(Some(_)) => {
                    return Err(ClientError::Security(format!(
                        "the pairing words of agent {:?} do not match; do not approve it",
                        issuer.name
                    )));
                }
                PairingCheck::Typed(None) => {
                    return Err(ClientError::Invalid(format!(
                        "agent {:?} is pending: compare its 6 pairing words first",
                        issuer.name
                    )));
                }
                PairingCheck::InPrompt => {}
            }
        }
        let profiles = self.issuer_profiles(&proxy_payload, &spec.profiles)?;
        let max_ttl_secs = spec.max_ttl_secs.unwrap_or(DEFAULT_SANDBOX_TTL_SECS);
        if !(MIN_SANDBOX_TTL_SECS..=MAX_SANDBOX_TTL_SECS).contains(&max_ttl_secs) {
            return Err(ClientError::Invalid(format!(
                "--max-ttl must be between {} minutes and {} hours",
                MIN_SANDBOX_TTL_SECS / 60,
                MAX_SANDBOX_TTL_SECS / 3600
            )));
        }
        let max_live = spec.max_live.unwrap_or(DEFAULT_LIVE_SANDBOXES);
        if !(1..=MAX_LIVE_SANDBOXES).contains(&max_live) {
            return Err(ClientError::Invalid(format!(
                "--max-live must be between 1 and {MAX_LIVE_SANDBOXES}"
            )));
        }
        let url = spec.url.trim().to_owned();
        klav_core::crypto::sandbox::check_proxy_url(&url).map_err(|e| {
            ClientError::Invalid(format!(
                "--url: {e} (give where a sandbox reaches the proxy: tls://host:port)"
            ))
        })?;

        let sandbox = IssuerGrant {
            proxy: Some(SandboxProxy {
                agent_id: proxy.id,
                public_identity: Blob::new(proxy.public.encode().to_vec()),
                url: url.clone(),
            }),
        };
        let current_policy = issuer_current
            .as_ref()
            .map_or_else(Policy::default, |p| p.policy.clone());
        // With or without projects: `klav agent approve` can give it some
        // later, and signs the policy that command is given, whose default
        // allows `inject` (ADR 0036 E6.2, Q-D).
        let inject_allowed = inject_allowed(&current_policy);
        let policy = if spec.inject_ask {
            inject_asks(current_policy)
        } else {
            current_policy
        };
        let issuer_next = match &issuer_current {
            Some(current) => {
                let mut next = current.clone();
                next.sandbox = Some(sandbox);
                next.policy = policy;
                (next.sandbox != current.sandbox || next.policy != current.policy)
                    .then_some(IssuerNext::Change(next))
            }
            None => Some(IssuerNext::First { policy, sandbox }),
        };
        let entry = SandboxIssuer {
            agent_id: issuer.id,
            public_identity: Blob::new(issuer_public.encode().to_vec()),
            profiles: profiles.clone(),
            max_ttl_secs,
            max_live,
        };
        let mut proxy_next = proxy_payload.clone();
        proxy_next.issuers.retain(|i| i.agent_id != issuer.id);
        proxy_next.issuers.push(entry);
        let proxy_next = (proxy_next.issuers != proxy_payload.issuers).then_some(proxy_next);
        if issuer_next.is_none() && proxy_next.is_none() {
            return Err(ClientError::Invalid(format!(
                "agent {:?} is already an issuer of the proxy {:?} with these profiles and limits",
                issuer.name, proxy.name
            )));
        }
        let first_on_account = !self.any_sandbox_grant().await?;
        let mut warnings = Vec::new();
        if first_on_account {
            warnings.push(OLDER_CLIENTS_ISSUERS.to_owned());
        } else if issuer_current.as_ref().is_none_or(|p| p.sandbox.is_none()) {
            // Only the account's first issuer gets the whole warning; every
            // agent that becomes one gets a grant older Klav cannot read.
            warnings.push(format!(
                "agent {:?} gets a grant in a format a Klav older than this one cannot read: if it runs an older Klav, its `run`, `inject` and MCP stop until it is updated",
                issuer.name
            ));
        }
        if inject_allowed && !spec.inject_ask {
            let holds = issuer_current
                .as_ref()
                .is_some_and(|p| !p.projects.is_empty());
            warnings.push(format!(
                "agent {:?} may `inject` without asking{}: it could pass a provider's token to the command that creates a sandbox, which is what sandboxes avoid (T171). Run it again with --inject-ask to make each `inject` ask you first",
                issuer.name,
                if holds {
                    ""
                } else {
                    " once it is approved for a project (a later `klav agent approve` signs the policy that command is given, and by default that policy allows `inject`)"
                }
            ));
        }
        if spec.inject_ask {
            warnings.push(format!(
                "the `inject: ask` this adds to agent {:?} lasts until its next `klav agent approve`, which signs only the policy that command is given: run it with `--ask inject` to keep it",
                issuer.name
            ));
        }
        let view = IssuerChangeView {
            issuer_id: issuer.id,
            issuer: issuer.name.clone(),
            pending,
            pairing_code: pairing_code(&issuer_public),
            proxy_id: proxy.id,
            proxy: proxy.name.clone(),
            remove: false,
            url,
            profiles,
            max_ttl_secs,
            max_live,
            inject_allowed,
            inject_ask: spec.inject_ask,
            first_on_account,
            proxy_base_version: proxy_payload.version,
            issuer_base_version: issuer_current.as_ref().map_or(0, |p| p.version),
            issuer_changes: issuer_next.is_some(),
            proxy_changes: proxy_next.is_some(),
            warnings,
        };
        Ok(PreparedIssuerChange {
            view,
            issuer_public,
            issuer_current,
            issuer_next,
            proxy_public: proxy.public,
            proxy_next,
        })
    }

    /// What [`Self::prepare_issuer_add`] would sign, with every check but
    /// the words: the person compares the words this shows.
    pub async fn preview_issuer_add(
        &mut self,
        agent: &str,
        spec: &IssuerSpec,
    ) -> ClientResult<IssuerChangeView> {
        Ok(self
            .prepare_issuer_add(agent, spec, PairingCheck::InPrompt)
            .await?
            .view)
    }

    /// Checks `klav proxy issuer remove <agent>`: the proxy's grant drops
    /// it first, then its own grant stops naming the proxy: with projects
    /// it loses `sandbox` (and goes back to the version they need);
    /// without, it keeps `sandbox` with no proxy, since a grant needs
    /// something in it. Running it again finishes a half-done one.
    pub async fn prepare_issuer_remove(
        &mut self,
        agent: &str,
    ) -> ClientResult<PreparedIssuerChange> {
        let proxy = self.current_proxy().await?;
        let issuer = self.agent(agent).await?;
        let issuer_public =
            PublicIdentity::decode(self.agent_info(issuer.id).await?.public_identity.as_bytes())?;
        let issuer_current = match self.agent_info(issuer.id).await?.grant {
            Some(g) => Some(self.open_grant(issuer.id, &issuer_public, &g)?),
            None => None,
        };
        let proxy_payload = proxy.payload.clone().unwrap_or_else(|| GrantPayload {
            v: GRANT_PAYLOAD_VERSION,
            account_id: self.account.account_id,
            agent_id: proxy.id,
            version: 0,
            issued_at: 0,
            policy: Policy::default(),
            projects: Vec::new(),
            items: Vec::new(),
            profiles: Vec::new(),
            issuers: Vec::new(),
            sandbox: None,
        });
        let mut proxy_next = proxy_payload.clone();
        proxy_next.issuers.retain(|i| i.agent_id != issuer.id);
        let proxy_next = (proxy_next.issuers != proxy_payload.issuers).then_some(proxy_next);
        let issuer_next = issuer_current.as_ref().and_then(|current| {
            let names_proxy = current
                .sandbox
                .as_ref()
                .and_then(|s| s.proxy.as_ref())
                .is_some_and(|p| p.agent_id == proxy.id);
            // With projects it keeps them and loses `sandbox`; without, a
            // grant needs `sandbox`, so it names no proxy (as after `use`).
            (names_proxy && issuer.status == AgentStatus::Active).then(|| {
                let mut next = current.clone();
                next.sandbox = if current.projects.is_empty() {
                    Some(klav_proto::agent::IssuerGrant { proxy: None })
                } else {
                    None
                };
                IssuerNext::Change(next)
            })
        });
        if proxy_next.is_none() && issuer_next.is_none() {
            return Err(ClientError::NotFound(format!(
                "agent {:?} among the issuers of the proxy {:?}",
                issuer.name, proxy.name
            )));
        }
        let view = IssuerChangeView {
            issuer_id: issuer.id,
            issuer: issuer.name.clone(),
            pending: false,
            pairing_code: pairing_code(&issuer_public),
            proxy_id: proxy.id,
            proxy: proxy.name.clone(),
            remove: true,
            url: String::new(),
            profiles: Vec::new(),
            max_ttl_secs: 0,
            max_live: 0,
            inject_allowed: false,
            inject_ask: false,
            first_on_account: false,
            proxy_base_version: proxy_payload.version,
            issuer_base_version: issuer_current.as_ref().map_or(0, |p| p.version),
            issuer_changes: issuer_next.is_some(),
            proxy_changes: proxy_next.is_some(),
            warnings: Vec::new(),
        };
        Ok(PreparedIssuerChange {
            view,
            issuer_public,
            issuer_current,
            issuer_next,
            proxy_public: proxy.public,
            proxy_next,
        })
    }

    /// Signs and uploads a checked issuer change. Adding signs the
    /// issuer's grant first, removing the proxy's: in between, the proxy
    /// does not list an issuer that names it, and refuses it.
    pub async fn commit_issuer_change(
        &mut self,
        prepared: PreparedIssuerChange,
    ) -> ClientResult<IssuerReport> {
        let PreparedIssuerChange {
            view,
            issuer_public,
            issuer_current,
            issuer_next,
            proxy_public,
            proxy_next,
        } = prepared;
        let mut report = IssuerReport {
            issuer: self.agent(&view.issuer_id.to_string()).await?,
            issuer_done: issuer_next.is_none(),
            proxy_done: proxy_next.is_none(),
            failed: None,
        };
        let floor = issuer_current
            .as_ref()
            .map_or(GRANT_PAYLOAD_VERSION, |p| p.v);
        if view.remove {
            if let Some(next) = proxy_next {
                match self.reissue_grant(view.proxy_id, &proxy_public, next).await {
                    Ok(_) => report.proxy_done = true,
                    Err(e) => {
                        report.failed = Some(format!("changing the proxy's grant: {e}"));
                        return Ok(report);
                    }
                }
            }
            if let Some(next) = issuer_next {
                match self
                    .sign_issuer(view.issuer_id, &issuer_public, next, floor)
                    .await
                {
                    Ok(issuer) => {
                        report.issuer = issuer;
                        report.issuer_done = true;
                    }
                    Err(e) => report.failed = Some(format!("changing the issuer's grant: {e}")),
                }
            }
        } else {
            if let Some(next) = issuer_next {
                match self
                    .sign_issuer(view.issuer_id, &issuer_public, next, floor)
                    .await
                {
                    Ok(issuer) => {
                        report.issuer = issuer;
                        report.issuer_done = true;
                    }
                    Err(e) => {
                        report.failed = Some(format!("changing the issuer's grant: {e}"));
                        return Ok(report);
                    }
                }
            }
            if let Some(next) = proxy_next {
                match self.reissue_grant(view.proxy_id, &proxy_public, next).await {
                    Ok(_) => report.proxy_done = true,
                    Err(e) => report.failed = Some(format!("changing the proxy's grant: {e}")),
                }
            }
        }
        Ok(report)
    }

    /// Re-signs every active issuer whose grant names a proxy other than
    /// `now` (the proxy setting just written) with `proxy: null` (ADR 0036
    /// §3, D7): the person makes it an issuer of the new one with `klav
    /// proxy issuer add`. Idempotent, so `klav proxy use` again finishes
    /// what failed.
    pub async fn resign_issuers(&mut self, now: Option<AgentId>) -> ClientResult<IssuerResign> {
        let mut out = IssuerResign::default();
        for agent in self.agents().await? {
            let names = agent
                .grant
                .as_ref()
                .and_then(|g| g.sandbox.as_ref())
                .and_then(|s| s.proxy.as_ref())
                .map(|p| p.agent_id);
            let Some(names) = names else { continue };
            if Some(names) == now || agent.status != AgentStatus::Active {
                continue;
            }
            let result = async {
                let info = self.agent_info(agent.id).await?;
                let public = PublicIdentity::decode(info.public_identity.as_bytes())?;
                let grant = info
                    .grant
                    .ok_or_else(|| ClientError::NotFound("its grant".into()))?;
                let mut payload = self.open_grant(agent.id, &public, &grant)?;
                payload.sandbox = Some(IssuerGrant { proxy: None });
                self.reissue_grant(agent.id, &public, payload).await
            }
            .await;
            match result {
                Ok(_) => out.done.push(agent.name),
                Err(e) => out.failed.push(format!("{}: {e}", agent.name)),
            }
        }
        Ok(out)
    }

    /// The agent `issuer` as an issuer candidate: its key, its grant as
    /// signed, and whether it is pending. Its key is either the one a
    /// grant this account signed vouches for, or (pending) the one whose
    /// words the person compares.
    async fn issuer_candidate(
        &mut self,
        issuer: &AgentView,
        proxy: AgentId,
    ) -> ClientResult<(PublicIdentity, Option<GrantPayload>, bool)> {
        if issuer.id == proxy {
            return Err(ClientError::Invalid(format!(
                "agent {:?} is the credential proxy: an issuer is another agent",
                issuer.name
            )));
        }
        if self.cache.revocations.contains_key(&issuer.id) {
            return Err(ClientError::Security(format!(
                "agent {:?} was revoked from this device",
                issuer.name
            )));
        }
        let info = self.agent_info(issuer.id).await?;
        let public = PublicIdentity::decode(info.public_identity.as_bytes())?;
        match info.status {
            AgentStatus::Pending => Ok((public, None, true)),
            AgentStatus::Active => {
                let grant = info.grant.ok_or_else(|| {
                    ClientError::Invalid(format!("agent {:?} has no grant", issuer.name))
                })?;
                let payload = self.open_grant(issuer.id, &public, &grant)?;
                if !payload.items.is_empty() || !payload.profiles.is_empty() {
                    return Err(ClientError::Invalid(format!(
                        "agent {:?} holds credentials one by one (a credential proxy): an issuer holds none",
                        issuer.name
                    )));
                }
                Ok((public, Some(payload), false))
            }
            other => Err(ClientError::Invalid(format!(
                "agent {:?} is {}; it cannot be an issuer",
                issuer.name,
                other.as_str()
            ))),
        }
    }

    /// `wanted` checked against the proxy's profiles: each one there, no
    /// repeats, at least one, at most [`MAX_ISSUER_PROFILES`].
    fn issuer_profiles(
        &self,
        proxy: &GrantPayload,
        wanted: &[String],
    ) -> ClientResult<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        for name in wanted {
            let name = name.trim();
            if !proxy.profiles.iter().any(|p| p.name == name) {
                return Err(ClientError::Invalid(format!(
                    "the proxy has no profile {name:?} (`klav proxy status` lists them)"
                )));
            }
            if !out.iter().any(|n| n == name) {
                out.push(name.to_owned());
            }
        }
        if out.is_empty() {
            return Err(ClientError::Invalid(
                "name at least one of the proxy's profiles with --profile".into(),
            ));
        }
        if out.len() > MAX_ISSUER_PROFILES {
            return Err(ClientError::Invalid(format!(
                "one issuer gets at most {MAX_ISSUER_PROFILES} profiles, so the confirmation can show them all"
            )));
        }
        Ok(out)
    }

    /// Whether any agent of the account already has a `v: 3` grant.
    async fn any_sandbox_grant(&mut self) -> ClientResult<bool> {
        Ok(self.agents().await?.iter().any(|a| {
            a.grant
                .as_ref()
                .is_some_and(|g| g.v >= GRANT_PAYLOAD_VERSION_SANDBOXES)
        }))
    }

    /// Signs the issuer's new grant: a change of its grant, or its first
    /// (no projects: an issuer holds no keys).
    async fn sign_issuer(
        &mut self,
        id: AgentId,
        public: &PublicIdentity,
        next: IssuerNext,
        floor: u32,
    ) -> ClientResult<AgentView> {
        match next {
            IssuerNext::Change(payload) => self.reissue_grant(id, public, payload).await,
            IssuerNext::First { policy, sandbox } => {
                self.issue_grant(
                    id,
                    public,
                    crate::agents::GrantSlot { version: 1, floor },
                    policy,
                    Vec::new(),
                    Some(sandbox),
                )
                .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_counts_as_allowed_by_default_or_by_an_allow_rule() {
        assert!(inject_allowed(&Policy::default()));
        let deny = Policy {
            rules: vec![Rule::new(Permission::Inject, Effect::Deny)],
            expires_at: None,
        };
        assert!(!inject_allowed(&deny));
        // An `allow` next to a broader `ask` asks.
        let mut both = Policy {
            rules: vec![Rule::new(Permission::Inject, Effect::Allow)],
            expires_at: None,
        };
        assert!(inject_allowed(&both));
        both = inject_asks(both);
        assert!(!inject_allowed(&both));
        let asks = inject_asks(Policy::default());
        assert!(!inject_allowed(&asks));
        // Asking twice adds one rule.
        assert_eq!(inject_asks(asks.clone()).rules.len(), asks.rules.len());
    }
}
