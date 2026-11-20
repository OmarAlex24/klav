//! The person's revocation of sandboxes (ADR 0036 E3.3, spec §13.11).
//!
//! The device signs `klav/v1/sig/sandbox-revoke` with the account identity
//! (no presence, like a pause: it only takes access away, ADR 0036 risk
//! 64) and sends it to `POST /v1/sandboxes/revoke`. The server logs it as
//! `sandbox.revoke_requested` and bars the sandboxes from then on;
//! `klav log verify` checks the event against the chain.

use klav_core::crypto::sandbox::{RevokeScope, RevokeToSign, sign_revoke};
use klav_core::ids::AgentId;
use klav_proto::Blob;
use klav_proto::sandbox::{
    PATH_PERSON_REVOKE, RevokeTarget, SCOPE_ALL, SandboxRevocation, SandboxRevoke, parse_scope,
};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, ClientResult};
use crate::session::{Unlocked, now_ms};

/// What a person's revocation did, for the apps and the CLI.
///
/// A revocation the server would not take because it says it already has
/// a later one of the same proxy and scope is an outcome, not an error: the
/// server says a later one stands; the verified list shows what it covers.
/// For `all` it does not cover sandboxes issued after it, so the person is
/// told it was not applied and may revoke again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RevokeOutcome {
    /// The server took it and logged it.
    Revoked {
        /// As the server stored it, with the sandboxes it covers.
        revocation: SandboxRevocation,
    },
    /// Not applied: the server has a revocation of the same proxy and
    /// scope signed later, at `later_at` (Unix ms), too far ahead of this
    /// device's clock to sign one after it.
    NotApplied {
        /// The proxy.
        proxy_id: AgentId,
        /// A sandbox ID, or `all`.
        scope: String,
        /// When the later revocation was signed.
        later_at: i64,
    },
}

impl RevokeOutcome {
    /// [`Unlocked::revoke_sandboxes`]'s result as an outcome: its
    /// [`ClientError::LaterRevocation`] becomes [`RevokeOutcome::NotApplied`];
    /// every other error stays one.
    pub fn of(
        proxy: AgentId,
        target: RevokeTarget,
        result: ClientResult<SandboxRevocation>,
    ) -> ClientResult<Self> {
        match result {
            Ok(revocation) => Ok(Self::Revoked { revocation }),
            Err(ClientError::LaterRevocation(later_at)) => Ok(Self::NotApplied {
                proxy_id: proxy,
                scope: match target {
                    RevokeTarget::All => SCOPE_ALL.to_owned(),
                    RevokeTarget::One(id) => id.to_string(),
                },
                later_at,
            }),
            Err(e) => Err(e),
        }
    }
}

/// The signed scope of `target`.
fn scope(target: RevokeTarget) -> RevokeScope {
    match target {
        RevokeTarget::All => RevokeScope::All,
        RevokeTarget::One(id) => RevokeScope::Sandbox(id),
    }
}

impl Unlocked {
    /// The person's revocation of `target` of the proxy `proxy`, signed at
    /// `at` (Unix ms).
    #[must_use]
    pub fn sign_sandbox_revoke(
        &self,
        proxy: AgentId,
        target: RevokeTarget,
        at: i64,
    ) -> SandboxRevoke {
        let signature = sign_revoke(
            &self.identity,
            &RevokeToSign {
                account: self.account.account_id,
                proxy,
                scope: scope(target),
                at_ms: u64::try_from(at).unwrap_or(0),
            },
        );
        SandboxRevoke {
            proxy_id: proxy,
            scope: match target {
                RevokeTarget::All => SCOPE_ALL.to_owned(),
                RevokeTarget::One(id) => id.to_string(),
            },
            at,
            signature: Blob::new(signature.to_bytes().to_vec()),
        }
    }

    /// Revokes one sandbox of `proxy`, or all of them, now. When the
    /// server already has a revocation of the same scope dated at or after
    /// now (another device's clock runs ahead), it is signed once more
    /// just after that one, if that is still within the server's ±5
    /// minutes ([`ClientError::LaterRevocation`], which carries the server's
    /// `last_at`, otherwise): a revocation only takes access away, and the
    /// person meant it now.
    pub async fn revoke_sandboxes(
        &mut self,
        proxy: AgentId,
        target: RevokeTarget,
    ) -> ClientResult<SandboxRevocation> {
        let first = self.sign_sandbox_revoke(proxy, target, now_ms());
        let last = match self.send_sandbox_revoke(&first).await {
            Err(ClientError::LaterRevocation(last)) => last,
            other => return other,
        };
        let now = now_ms();
        let at = now.max(last.saturating_add(1));
        if at - now > crate::audit::CLOCK_SKEW_MS {
            return Err(ClientError::LaterRevocation(last));
        }
        let again = self.sign_sandbox_revoke(proxy, target, at);
        match self.send_sandbox_revoke(&again).await {
            // The server's clock disagrees with ours on the ±5 minutes.
            Err(ClientError::Api { status: 400, .. }) => Err(ClientError::LaterRevocation(last)),
            other => other,
        }
    }

    /// [`Self::revoke_sandboxes`], with a later revocation as
    /// [`RevokeOutcome::NotApplied`] instead of an error.
    pub async fn revoke_sandboxes_outcome(
        &mut self,
        proxy: AgentId,
        target: RevokeTarget,
    ) -> ClientResult<RevokeOutcome> {
        let result = self.revoke_sandboxes(proxy, target).await;
        RevokeOutcome::of(proxy, target, result)
    }

    /// Sends a signed revocation and checks the server's answer
    /// ([`check_answer`]).
    async fn send_sandbox_revoke(
        &mut self,
        revoke: &SandboxRevoke,
    ) -> ClientResult<SandboxRevocation> {
        // The server answers an older one with the `409` and `last_at` of
        // a pause; here it is a revocation's.
        let stored: SandboxRevocation = self
            .send_json(Method::POST, PATH_PERSON_REVOKE, revoke)
            .await
            .map_err(|e| match e {
                ClientError::LaterPause(last) => ClientError::LaterRevocation(last),
                other => other,
            })?;
        check_answer(revoke, &stored)?;
        Ok(stored)
    }
}

/// The server's answer must be the revocation sent and, for one sandbox,
/// cover exactly that sandbox; otherwise [`ClientError::Security`]. For
/// `all`, the sandboxes it lists are the server's word: the verified list
/// shows each one it covers as revoking. Either failure says the server may
/// have stored the revocation anyway, in words that fit the CLI and the
/// apps: both have the list of sandboxes (`klav proxy sandboxes`).
fn check_answer(sent: &SandboxRevoke, stored: &SandboxRevocation) -> ClientResult<()> {
    if stored.proxy_id != sent.proxy_id
        || stored.scope != sent.scope
        || stored.at != sent.at
        || stored.signature != sent.signature
    {
        return Err(ClientError::Security(
            "the server answered a revocation of sandboxes with another one. The server may \
             have stored the revocation; the list of sandboxes shows it"
                .into(),
        ));
    }
    if let Ok(RevokeTarget::One(id)) = parse_scope(&sent.scope)
        && stored.sandbox_ids != [id]
    {
        return Err(ClientError::Security(format!(
            "the server answered the revocation of sandbox {id} with a list of sandboxes that is \
             not exactly that one. The server may have stored the revocation; the list of \
             sandboxes shows it"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_core::ids::SandboxId;

    /// Only a later revocation becomes an outcome; it names the scope the
    /// person asked for, and every other error stays an error.
    #[test]
    fn a_later_revocation_is_an_outcome_and_the_rest_stay_errors() {
        let proxy = AgentId::generate();
        let id = SandboxId::generate();
        for (target, scope) in [
            (RevokeTarget::All, SCOPE_ALL.to_owned()),
            (RevokeTarget::One(id), id.to_string()),
        ] {
            let outcome =
                RevokeOutcome::of(proxy, target, Err(ClientError::LaterRevocation(42))).unwrap();
            assert_eq!(
                outcome,
                RevokeOutcome::NotApplied {
                    proxy_id: proxy,
                    scope,
                    later_at: 42
                }
            );
        }
        for e in [
            ClientError::LaterPause(42),
            ClientError::Rollback("old".into()),
            ClientError::Security("bad".into()),
        ] {
            assert!(RevokeOutcome::of(proxy, RevokeTarget::All, Err(e)).is_err());
        }
        let json = serde_json::to_value(RevokeOutcome::NotApplied {
            proxy_id: proxy,
            scope: "all".into(),
            later_at: 7,
        })
        .unwrap();
        assert_eq!(json["outcome"], "not_applied");
    }

    /// The answer to one sandbox's revocation must cover exactly it: none,
    /// another one, or that one with another are a security error. An
    /// `all` takes the server's list as it comes.
    #[test]
    fn one_sandboxs_answer_must_cover_exactly_it() {
        let proxy = AgentId::generate();
        let id = SandboxId::generate();
        let sent = |scope: String| SandboxRevoke {
            proxy_id: proxy,
            scope,
            at: 10,
            signature: Blob::new(vec![7; 64]),
        };
        let answer = |sent: &SandboxRevoke, ids: Vec<SandboxId>| SandboxRevocation {
            seq: 4,
            proxy_id: sent.proxy_id,
            scope: sent.scope.clone(),
            at: sent.at,
            signature: sent.signature.clone(),
            sandbox_ids: ids,
        };
        let one = sent(id.to_string());
        assert!(check_answer(&one, &answer(&one, vec![id])).is_ok());
        for ids in [
            vec![],
            vec![SandboxId::generate()],
            vec![id, SandboxId::generate()],
        ] {
            assert!(
                matches!(
                    check_answer(&one, &answer(&one, ids.clone())),
                    Err(ClientError::Security(_))
                ),
                "{ids:?}"
            );
        }
        let all = sent(SCOPE_ALL.to_owned());
        for ids in [vec![], vec![id, SandboxId::generate()]] {
            assert!(check_answer(&all, &answer(&all, ids)).is_ok());
        }
        let mut other = answer(&one, vec![id]);
        other.at = 11;
        assert!(matches!(
            check_answer(&one, &other),
            Err(ClientError::Security(_))
        ));
    }
}
