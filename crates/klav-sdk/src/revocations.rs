//! The credential proxy's side of the person's revocation of sandboxes
//! (ADR 0036 E3.3, spec §13.11): it reads them by their cursor,
//! `GET /v1/agent/sandboxes/revocations?since=`, and checks each against
//! the account's pinned identity before acting on it. The server only
//! relays them: a revocation it made up, or one for another proxy, fails
//! here.

use klav_client::{ClientError, ClientResult, api};
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::sandbox::{RevokeScope, RevokeToSign, verify_revoke};
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::{AccountId, AgentId, SandboxId};
use klav_proto::sandbox::{
    MAX_REVOCATIONS_PAGE, PATH_REVOCATIONS, RevokeTarget, SandboxRevocation, SandboxRevocations,
    parse_scope,
};
use reqwest::Method;

use crate::Agent;

/// A revocation by the person, checked: the sandboxes it covers, and the
/// `at` the proxy's `person` end answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedRevocation {
    /// Its position in the account's log: the cursor to ask from next.
    pub seq: u64,
    /// When the person revoked, as signed (Unix ms).
    pub at: i64,
    /// One sandbox, or those of an `all` as the server listed them from the
    /// log (that list is not signed; `all` means every one of the proxy's
    /// sandboxes the log issued before it, so it can only name the proxy's
    /// own).
    pub sandbox_ids: Vec<SandboxId>,
}

/// One page of revocations, checked, in log order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationPage {
    /// The revocations after the cursor asked from.
    pub revocations: Vec<CheckedRevocation>,
    /// More after the last one.
    pub more: bool,
}

/// Checks `r`, read after the cursor `since`, as one of the person's
/// revocations of `proxy`'s sandboxes signed by the account `account_id`
/// with `account`.
pub fn check_revocation(
    account: &PublicIdentity,
    account_id: AccountId,
    proxy: AgentId,
    since: u64,
    r: &SandboxRevocation,
) -> Result<CheckedRevocation, String> {
    if r.seq <= since {
        return Err("it is not after the cursor asked from".into());
    }
    if r.proxy_id != proxy {
        return Err("it is for another proxy".into());
    }
    let at_ms = u64::try_from(r.at).map_err(|_| "it has no time".to_owned())?;
    if at_ms == 0 {
        return Err("it has no time".into());
    }
    let target = parse_scope(&r.scope)?;
    let signature: [u8; SIGNATURE_LEN] = r
        .signature
        .as_bytes()
        .try_into()
        .map_err(|_| "its signature has a wrong length".to_owned())?;
    let scope = match target {
        RevokeTarget::All => RevokeScope::All,
        RevokeTarget::One(id) => RevokeScope::Sandbox(id),
    };
    verify_revoke(
        account,
        &RevokeToSign {
            account: account_id,
            proxy,
            scope,
            at_ms,
        },
        &Signature::from_bytes(signature),
    )
    .map_err(|_| "the account did not sign it".to_owned())?;
    match target {
        RevokeTarget::One(id) if r.sandbox_ids != [id] => {
            return Err("it lists other sandboxes than the one signed".into());
        }
        RevokeTarget::All if r.sandbox_ids.windows(2).any(|w| w[0] >= w[1]) => {
            return Err("its list of sandboxes is not sorted once each".into());
        }
        _ => {}
    }
    Ok(CheckedRevocation {
        seq: r.seq,
        at: r.at,
        sandbox_ids: r.sandbox_ids.clone(),
    })
}

/// Longest page of revocations read (bytes), well under the 128 MiB of
/// [`api::json`]: 100 revocations (`MAX_REVOCATIONS_PAGE`) of an `all` over
/// 4096 sandboxes each, at about 40 bytes an ID, fit. Nothing caps the IDs
/// of one `all` (a proxy may have any number of issuers, each up to its
/// `max_live`), so this bounds memory, not what the server may list.
pub const MAX_REVOCATIONS_RESPONSE: usize = 16 * 1024 * 1024;

impl Agent {
    /// The person's revocations of this agent's sandboxes after the cursor
    /// `since` (a revocation's `seq`; `0` for all), each checked against
    /// the pinned account identity ([`check_revocation`]). One that fails
    /// fails the page ([`ClientError::Security`]): the caller keeps its
    /// cursor and acts on none of them.
    pub async fn sandbox_revocations(&self, since: u64) -> ClientResult<RevocationPage> {
        let res = self
            .send(
                Method::GET,
                &format!("{PATH_REVOCATIONS}?since={since}"),
                None,
            )
            .await?;
        if !res.status().is_success() {
            return Err(api::error(res).await);
        }
        let bytes = api::read_limited(res, MAX_REVOCATIONS_RESPONSE).await?;
        let page: SandboxRevocations = serde_json::from_slice(&bytes)
            .map_err(|e| ClientError::Network(format!("invalid response: {e}")))?;
        if page.revocations.len() > MAX_REVOCATIONS_PAGE {
            return Err(ClientError::Security(
                "the server sent a longer page of revocations than it may".into(),
            ));
        }
        let account = self.account_identity()?;
        let account_id = self
            .config
            .account_id
            .ok_or_else(|| ClientError::Invalid("the account is not known yet".into()))?;
        let mut last = since;
        let mut revocations = Vec::with_capacity(page.revocations.len());
        for r in &page.revocations {
            let checked =
                check_revocation(&account, account_id, self.id(), last, r).map_err(|e| {
                    ClientError::Security(format!("a revocation of sandboxes the server sent: {e}"))
                })?;
            last = checked.seq;
            revocations.push(checked);
        }
        Ok(RevocationPage {
            revocations,
            more: page.more,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_core::crypto::identity::IdentityKeyPair;
    use klav_core::crypto::sandbox::sign_revoke;
    use klav_proto::Blob;
    use klav_proto::sandbox::SCOPE_ALL;

    const AT: i64 = 1_800_000_000_000;

    struct World {
        account: IdentityKeyPair,
        account_id: AccountId,
        proxy: AgentId,
    }

    impl World {
        fn new() -> Self {
            Self {
                account: IdentityKeyPair::generate(),
                account_id: AccountId::generate(),
                proxy: AgentId::generate(),
            }
        }

        fn signed_by(
            &self,
            key: &IdentityKeyPair,
            seq: u64,
            one: Option<SandboxId>,
            ids: Vec<SandboxId>,
        ) -> SandboxRevocation {
            let signature = sign_revoke(
                key,
                &RevokeToSign {
                    account: self.account_id,
                    proxy: self.proxy,
                    scope: one.map_or(RevokeScope::All, RevokeScope::Sandbox),
                    at_ms: u64::try_from(AT).unwrap(),
                },
            );
            SandboxRevocation {
                seq,
                proxy_id: self.proxy,
                scope: one.map_or_else(|| SCOPE_ALL.to_owned(), |id| id.to_string()),
                at: AT,
                signature: Blob::new(signature.to_bytes().to_vec()),
                sandbox_ids: ids,
            }
        }

        fn revocation(
            &self,
            seq: u64,
            one: Option<SandboxId>,
            ids: Vec<SandboxId>,
        ) -> SandboxRevocation {
            self.signed_by(&self.account, seq, one, ids)
        }

        fn check(&self, since: u64, r: &SandboxRevocation) -> Result<CheckedRevocation, String> {
            check_revocation(self.account.public(), self.account_id, self.proxy, since, r)
        }
    }

    fn sorted(mut ids: Vec<SandboxId>) -> Vec<SandboxId> {
        ids.sort();
        ids
    }

    #[test]
    fn a_revocation_the_account_signed_for_this_proxy_is_taken() {
        let w = World::new();
        let (a, b) = (SandboxId::generate(), SandboxId::generate());
        let one = w.check(0, &w.revocation(3, Some(a), vec![a])).expect("one");
        assert_eq!((one.seq, one.at, one.sandbox_ids), (3, AT, vec![a]));
        let all = w
            .check(3, &w.revocation(7, None, sorted(vec![a, b])))
            .expect("all");
        assert_eq!(all.sandbox_ids, sorted(vec![a, b]));
        // An `all` that covers nothing live is still a revocation.
        assert!(w.check(7, &w.revocation(9, None, Vec::new())).is_ok());
    }

    #[test]
    fn a_made_up_reshaped_or_misplaced_revocation_fails() {
        let w = World::new();
        let (a, b) = (SandboxId::generate(), SandboxId::generate());
        let fails = |r: SandboxRevocation, since: u64, why: &str| {
            let e = w.check(since, &r).expect_err(why);
            assert!(e.contains(why), "{e}");
        };
        // Signed by another key: the server cannot make one up.
        fails(
            w.signed_by(&IdentityKeyPair::generate(), 1, Some(a), vec![a]),
            0,
            "did not sign",
        );
        // Signed for one sandbox, sent as another, or as `all`.
        let mut r = w.revocation(1, Some(a), vec![a]);
        r.scope = b.to_string();
        r.sandbox_ids = vec![b];
        fails(r, 0, "did not sign");
        let mut r = w.revocation(1, Some(a), vec![a]);
        r.scope = SCOPE_ALL.into();
        fails(r, 0, "did not sign");
        // Another time than the one signed.
        let mut r = w.revocation(1, Some(a), vec![a]);
        r.at += 1;
        fails(r, 0, "did not sign");
        // Signed by this account's key for another account: the account ID
        // is in the signed bytes (review of #348, 7d).
        let signature = sign_revoke(
            &w.account,
            &RevokeToSign {
                account: AccountId::generate(),
                proxy: w.proxy,
                scope: RevokeScope::Sandbox(a),
                at_ms: u64::try_from(AT).unwrap(),
            },
        );
        let mut r = w.revocation(1, Some(a), vec![a]);
        r.signature = Blob::new(signature.to_bytes().to_vec());
        fails(r, 0, "did not sign");
        // Another proxy's.
        let mut r = w.revocation(1, Some(a), vec![a]);
        r.proxy_id = AgentId::generate();
        fails(r, 0, "another proxy");
        // One sandbox signed, more listed.
        fails(w.revocation(1, Some(a), vec![a, b]), 0, "other sandboxes");
        // An `all` listed out of order or twice.
        let mut ids = sorted(vec![a, b]);
        ids.reverse();
        fails(w.revocation(1, None, ids), 0, "not sorted");
        fails(w.revocation(1, None, vec![a, a]), 0, "not sorted");
        // Not after the cursor: a replay of one already read.
        fails(w.revocation(4, Some(a), vec![a]), 4, "not after the cursor");
        // No time.
        let mut r = w.revocation(1, Some(a), vec![a]);
        r.at = 0;
        fails(r, 0, "no time");
        // A scope that is neither.
        let mut r = w.revocation(1, Some(a), vec![a]);
        r.scope = "every".into();
        fails(r, 0, "scope");
        // A signature of the wrong length.
        let mut r = w.revocation(1, Some(a), vec![a]);
        r.signature = Blob::new(vec![0; 10]);
        fails(r, 0, "wrong length");
    }
}
