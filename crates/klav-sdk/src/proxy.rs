//! One call of the credential proxy (ADR 0036 §2): the proxy, an agent
//! with a per-item grant, asks the server for one item for one HTTP
//! request it is about to build, and opens it with the item key its grant
//! carries (kind `0x23`).
//!
//! The authorization is asked for **on every call** and never cached: the
//! server evaluates the policy, logs the access (method, host and path,
//! never bodies or headers) and applies `ask`, revocation and the pause;
//! this runtime evaluates the same policy again, before the call and with
//! the tags of the version delivered. A `2xx` the local policy says needs
//! the person is only accepted with an approval the account signed for
//! exactly this request: same item, host, method and path, byte for byte.

use std::time::Duration;

use klav_client::{ClientError, ClientResult};
use klav_core::ids::{ApprovalId, ItemId};
use klav_core::model::{Item, SealedItem, open_item};
use klav_core::policy::{self, Decision, Effect, Permission, Target};
use klav_proto::agent::{AccessGranted, AccessRequest, ApprovalStatus, Claims, PendingApproval};
use reqwest::{Method, StatusCode};

use crate::session::{Session, forbidden, now_secs};

/// What one proxied request is: the item it needs and where it goes.
#[derive(Debug, Clone)]
pub struct ProxyCall<'a> {
    /// The granted item (a profile's `item_id`).
    pub item: ItemId,
    /// The upstream host, normalized (the profile's).
    pub host: &'a str,
    /// The request method, exactly as sent upstream.
    pub method: &'a str,
    /// The request path without query, exactly the bytes sent upstream.
    pub path: &'a str,
    /// The item's tags as last delivered (empty before the first call):
    /// sent as claims, and the policy is checked again with the real ones.
    pub tags: &'a [String],
    /// Why: shown to the person and kept in the audit log.
    pub reason: &'a str,
    /// The sandbox the call comes from, through the pinned channel (ADR
    /// 0036 E3.3): the server refuses it unless the sandbox and its issuer
    /// are live (`403 sandbox_revoked`).
    pub sandbox: Option<klav_core::ids::SandboxId>,
    /// An MCP `tools/call` (ADR 0049 §5.4): the tool's name, in the tool
    /// grammar, evaluated by the policy and sent as `claims.mcp_tool`.
    pub mcp_tool: Option<&'a str>,
    /// The argument digest's text form, sent as `claims.mcp_args` with
    /// `mcp_tool` (both or neither).
    pub mcp_args: Option<&'a str>,
    /// The local client the call comes from (ADR 0049 §3.2), sent as
    /// `local_client` only while the account's `mcp_gateway` switch is on.
    pub local_client: Option<&'a str>,
}

/// What the server answered.
pub enum ProxyAccess {
    /// The item, decrypted, and the approval the server used, if any.
    Granted {
        /// The item.
        item: Box<Item>,
        /// Its version (never lower than the one passed as `seen`).
        version: u64,
        /// The approval that let it through.
        approval_id: Option<ApprovalId>,
    },
    /// The person has to decide first; a retry of the same request uses
    /// the decision once she takes it (ADR 0015 §2).
    Pending {
        /// The approval.
        approval_id: ApprovalId,
        /// Until when she can decide (Unix ms).
        expires_at: i64,
    },
}

impl Session {
    /// The policy decision for `call` under the grant of this session, as
    /// the server takes it (grants name vaults and projects by ID only).
    pub fn evaluate_proxy(&self, call: &ProxyCall<'_>, tags: &[String]) -> Decision {
        let Some(granted) = self.grant.items.get(&call.item) else {
            return Decision {
                effect: Effect::Deny,
                reason: policy::Reason::OutOfScope,
            };
        };
        policy::evaluate(
            &self.grant.payload.policy,
            &policy::Request {
                permission: Permission::Proxy,
                vault: Target {
                    id: granted.ctx.vault,
                    name: String::new(),
                },
                project: Target {
                    id: granted.ctx.project,
                    name: String::new(),
                },
                tags: tags.to_vec(),
                domain: Some(call.host.to_owned()),
                item: Some(call.item),
                method: Some(call.method.to_owned()),
                path: Some(call.path.to_owned()),
                now: now_secs(),
                mcp_tool: call.mcp_tool.map(str::to_owned),
            },
        )
    }

    /// Asks the server for `call.item` for this one request and opens it.
    /// `seen` is the highest version of the item this proxy already
    /// opened: an older one is a rollback and is refused.
    ///
    /// Errors: [`ClientError::Denied`] when either policy refuses (or the
    /// person denied an approval), [`ClientError::Paused`] when agents are
    /// paused, [`ClientError::Network`] when the server does not answer,
    /// [`ClientError::Security`] when the server let through what this
    /// runtime cannot verify.
    pub async fn proxy_access(&self, call: &ProxyCall<'_>, seen: u64) -> ClientResult<ProxyAccess> {
        crate::text::check_declared("reason", call.reason)?;
        let decision = self.evaluate_proxy(call, call.tags);
        let denied = || match call.mcp_tool {
            Some(tool) => ClientError::Denied(format!(
                "the policy does not allow the tool {tool} on {}",
                call.host
            )),
            None => ClientError::Denied(format!(
                "the policy does not allow {} {} on {}",
                call.method, call.path, call.host
            )),
        };
        let granted_key = self
            .grant
            .items
            .get(&call.item)
            .ok_or_else(|| ClientError::NotFound(format!("item {} in the grant", call.item)))?;
        // Asked even when the policy here denies, so that the server logs
        // the denial (and alerts); nothing is decrypted then.
        let body = AccessRequest {
            item_id: call.item,
            permission: Permission::Proxy,
            reason: call.reason.trim().to_owned(),
            claims: Claims {
                tags: call.tags.to_vec(),
                domain: Some(call.host.to_owned()),
                method: Some(call.method.to_owned()),
                path: Some(call.path.to_owned()),
                mcp_tool: call.mcp_tool.map(str::to_owned),
                mcp_args: call.mcp_args.map(str::to_owned),
            },
            approval_id: None,
            task_id: None,
            include_attachments: false,
            sandbox: call.sandbox,
            local_client: call.local_client.map(str::to_owned),
        };
        let bytes =
            serde_json::to_vec(&body).map_err(|e| ClientError::Invalid(format!("request: {e}")))?;
        let res = self
            .agent
            .send(Method::POST, "/v1/agent/access", Some(&bytes))
            .await?;
        match res.status() {
            StatusCode::ACCEPTED => {
                let p: PendingApproval = klav_client::api::json(res).await?;
                if decision.effect == Effect::Deny {
                    return Err(denied());
                }
                Ok(ProxyAccess::Pending {
                    approval_id: p.pending_approval_id,
                    expires_at: p.expires_at,
                })
            }
            // A sandbox's call the server bars keeps its code: the proxy
            // ends nothing on it, and tells the sandbox it is over.
            StatusCode::FORBIDDEN if call.sandbox.is_some() => {
                Err(match klav_client::api::json::<serde_json::Value>(res).await {
                    Err(
                        e @ ClientError::Api {
                            code: Some(klav_proto::ErrorCode::SandboxRevoked),
                            ..
                        },
                    ) => e,
                    Err(ClientError::Paused(p)) => ClientError::Paused(p),
                    Err(ClientError::AccountDeleting(at)) => ClientError::AccountDeleting(at),
                    Err(ClientError::Api { message, .. }) => ClientError::Denied(format!(
                        "the server refused it; {}",
                        crate::text::untrusted(&message)
                    )),
                    _ => ClientError::Denied("the server refused it; forbidden".into()),
                })
            }
            StatusCode::FORBIDDEN => Err(forbidden(res).await),
            // Passed on as a `401`, so the proxy tells it apart from a
            // denial by its status, not by its words.
            StatusCode::UNAUTHORIZED => Err(ClientError::Api {
                status: 401,
                code: None,
                message: "the server refused the proxy's signature (revoked or unknown agent, or a clock off by more than 5 minutes)".into(),
                current_version: None,
            }),
            _ if decision.effect == Effect::Deny => Err(denied()),
            _ => {
                let granted: AccessGranted = klav_client::api::json(res).await?;
                if decision.effect == Effect::Ask {
                    self.proxy_backed(call, granted.approval_id).await?;
                }
                let wire = &granted.item;
                if wire.id != call.item
                    || wire.vault_id != granted_key.ctx.vault
                    || wire.project_id != granted_key.ctx.project
                {
                    return Err(ClientError::Security(
                        "the server returned another item than the one granted".into(),
                    ));
                }
                if wire.version < seen {
                    return Err(ClientError::Rollback(format!(
                        "item {} went back from version {seen} to {}",
                        call.item, wire.version
                    )));
                }
                let sealed = SealedItem {
                    overview: wire
                        .overview
                        .as_ref()
                        .ok_or_else(|| ClientError::Corrupt("item without overview".into()))?
                        .as_bytes()
                        .to_vec(),
                    details: wire
                        .details
                        .as_ref()
                        .ok_or_else(|| ClientError::Corrupt("item without details".into()))?
                        .as_bytes()
                        .to_vec(),
                };
                let item = open_item(&granted_key.key, &granted_key.ctx, wire.version, &sealed)?;
                // The policy again, with the tags of the version delivered.
                let real = self.evaluate_proxy(call, item.tags());
                if real.effect == Effect::Deny {
                    return Err(denied());
                }
                if real.effect > decision.effect {
                    self.proxy_backed(call, granted.approval_id).await?;
                }
                Ok(ProxyAccess::Granted {
                    item: Box::new(item),
                    version: wire.version,
                    approval_id: granted.approval_id,
                })
            }
        }
    }

    /// A `2xx` for `call` when the policy here says `ask`: the server must
    /// name the approval it used, approved and signed by the account, still
    /// serving, and for exactly this request (item, host, method and path,
    /// the last two byte for byte). Tasks never cover `proxy`.
    async fn proxy_backed(
        &self,
        call: &ProxyCall<'_>,
        returned: Option<ApprovalId>,
    ) -> ClientResult<()> {
        let id = returned.ok_or_else(|| {
            ClientError::Security(
                "the server let a proxied call through without an approval, but the proxy's policy asks the person: its answer is refused".into(),
            )
        })?;
        let info = self.agent.approval(id, Duration::ZERO).await?;
        let request: klav_proto::agent::ApprovalRequest =
            serde_json::from_slice(info.request.as_bytes())
                .map_err(|_| ClientError::Corrupt("approval request".into()))?;
        if info.id != id
            || info.agent_id != self.agent.id()
            || request.approval_id != id
            || request.agent_id != self.agent.id()
        {
            return Err(ClientError::Security(
                "the server answered with another approval".into(),
            ));
        }
        if info.status != ApprovalStatus::Approved {
            return Err(ClientError::Security(format!(
                "the server let a proxied call through with approval {id}, which is not approved"
            )));
        }
        // Signed by the account and still serving (this request just spent
        // an approve-once decision).
        self.check_approval(&info, true).map_err(|e| match e {
            ClientError::Invalid(m) => ClientError::Security(format!(
                "the server let a proxied call through with an approval that no longer serves: {m}"
            )),
            other => other,
        })?;
        let granted = self.grant.items.get(&call.item);
        let fits = request.permission == Permission::Proxy
            && request.item_id == Some(call.item)
            && granted.is_some_and(|g| {
                request.vault_id == g.ctx.vault && request.project_id == g.ctx.project
            })
            && request.claims.domain.as_deref() == Some(call.host)
            && request.claims.method.as_deref() == Some(call.method)
            && request.claims.path.as_deref() == Some(call.path)
            && mcp_fits(call, &request, info.lease_until.unwrap_or(0) > 0);
        if !fits {
            return Err(ClientError::Security(format!(
                "the server let a proxied call through with approval {id}, which is for another request"
            )));
        }
        Ok(())
    }
}

/// Whether an approval's MCP fields fit `call` (ADR 0049 §5.4, T261): the
/// same tool always; the same argument digest, unless the person signed a
/// lease (`lease_until` is under the account's signature, checked before
/// this); and, when the approval names its caller, this call's caller,
/// which a call from a local client must have. A call without a tool fits
/// only an approval without one.
fn mcp_fits(
    call: &ProxyCall<'_>,
    request: &klav_proto::agent::ApprovalRequest,
    leased: bool,
) -> bool {
    let claims = &request.claims;
    if claims.mcp_tool.as_deref() != call.mcp_tool {
        return false;
    }
    if claims.mcp_args.as_deref() != call.mcp_args
        && !(leased && call.mcp_tool.is_some() && claims.mcp_args.is_some())
    {
        return false;
    }
    match &request.caller {
        Some(caller) => {
            caller.sandbox_id == call.sandbox && caller.local_client.as_deref() == call.local_client
        }
        None => call.local_client.is_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_core::ids::{AgentId, ProjectId, SandboxId, VaultId};
    use klav_proto::agent::{ApprovalCaller, ApprovalRequest};

    fn approval(
        tool: Option<&str>,
        args: Option<&str>,
        caller: Option<ApprovalCaller>,
    ) -> ApprovalRequest {
        ApprovalRequest {
            v: 1,
            approval_id: ApprovalId::generate(),
            agent_id: AgentId::generate(),
            agent_name: "klav-proxy".into(),
            permission: Permission::Proxy,
            vault_id: VaultId::generate(),
            project_id: ProjectId::generate(),
            item_id: None,
            reason: "credential proxy call".into(),
            claims: Claims {
                mcp_tool: tool.map(str::to_owned),
                mcp_args: args.map(str::to_owned),
                ..Claims::default()
            },
            grant_version: 1,
            requested_at: 0,
            caller,
        }
    }

    fn call<'a>(
        tool: Option<&'a str>,
        args: Option<&'a str>,
        sandbox: Option<SandboxId>,
        local: Option<&'a str>,
    ) -> ProxyCall<'a> {
        ProxyCall {
            item: ItemId::generate(),
            host: "api.example.com",
            method: "POST",
            path: "/mcp",
            tags: &[],
            reason: "credential proxy call",
            sandbox,
            mcp_tool: tool,
            mcp_args: args,
            local_client: local,
        }
    }

    /// ADR 0049 §5.4 (T261): what the proxy accepts as the approval behind
    /// a server's "allowed" for an MCP call.
    #[test]
    fn an_approval_fits_only_its_tool_its_arguments_unless_leased_and_its_caller() {
        let local = |name: &str| {
            Some(ApprovalCaller {
                sandbox_id: None,
                local_client: Some(name.into()),
            })
        };
        let sandbox = SandboxId::generate();
        let in_sandbox = Some(ApprovalCaller {
            sandbox_id: Some(sandbox),
            local_client: None,
        });
        let a = approval(Some("delete_x"), Some("A"), local("claude-code"));
        let mine = |tool, args| call(tool, args, None, Some("claude-code"));
        // The same tool, arguments and caller.
        assert!(mcp_fits(&mine(Some("delete_x"), Some("A")), &a, false));
        // Another tool, leased or not.
        assert!(!mcp_fits(&mine(Some("delete_y"), Some("A")), &a, false));
        assert!(!mcp_fits(&mine(Some("delete_y"), Some("A")), &a, true));
        // Other arguments: only under a signed lease.
        assert!(!mcp_fits(&mine(Some("delete_x"), Some("B")), &a, false));
        assert!(mcp_fits(&mine(Some("delete_x"), Some("B")), &a, true));
        // Another caller, leased or not.
        let other = call(Some("delete_x"), Some("A"), None, Some("cursor"));
        assert!(!mcp_fits(&other, &a, true));
        let from_sandbox = call(Some("delete_x"), Some("A"), Some(sandbox), None);
        assert!(!mcp_fits(&from_sandbox, &a, true));
        // A local client's call needs an approval that names it.
        let unnamed = approval(Some("delete_x"), Some("A"), None);
        assert!(!mcp_fits(
            &mine(Some("delete_x"), Some("A")),
            &unnamed,
            true
        ));
        // A sandbox's call fits its own sandbox, and one without a caller
        // (the switch was off when it was asked).
        let for_sandbox = approval(Some("delete_x"), Some("A"), in_sandbox);
        assert!(mcp_fits(&from_sandbox, &for_sandbox, false));
        assert!(!mcp_fits(
            &call(
                Some("delete_x"),
                Some("A"),
                Some(SandboxId::generate()),
                None
            ),
            &for_sandbox,
            false
        ));
        assert!(mcp_fits(&from_sandbox, &unnamed, false));
        // A tool's approval never backs a call without a tool, and the
        // other way round.
        assert!(!mcp_fits(&call(None, None, None, None), &unnamed, true));
        let plain = approval(None, None, None);
        assert!(mcp_fits(&call(None, None, None, None), &plain, false));
        assert!(!mcp_fits(
            &call(Some("delete_x"), Some("A"), None, None),
            &plain,
            true
        ));
    }
}
