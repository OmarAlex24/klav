//! The device's check of a credential proxy's heartbeat (ADR 0036 E3.3,
//! spec §13.12).
//!
//! The heartbeat is the proxy's signed request `PUT
//! /v1/agent/sandboxes/state`. The server keeps only the last one per
//! proxy, out of the log, and hands it back as it was signed. What the
//! device may believe of it comes from the checks here, never from the
//! server:
//!
//! - the proxy signed it, with the key a verified `agent.granted` vouches
//!   for (the caller passes that identity);
//! - it carries the store epoch of the proxy's last `sandbox.store_reset`
//!   in the verified chain ([`StoreEpoch`] in the verify report);
//! - within that epoch, its `seq` is not below the highest this device saw
//!   (the caller keeps that watermark);
//! - its age is measured from the `sent_at_ms` the proxy signed.
//!
//! A heartbeat says when each sandbox was last connected, nothing more. It
//! never makes a sandbox live, ended or revoked: that comes from the chain
//! alone. A sandbox it names that the chain does not show live is ignored
//! by the caller.

use klav_core::crypto::agent::{self, NONCE_LEN, SignedRequest};
use klav_core::crypto::identity::PublicIdentity;
use klav_core::crypto::sign::{SIGNATURE_LEN, Signature};
use klav_core::ids::AgentId;
use klav_proto::Blob;
use klav_proto::audit::AgentProof;
use klav_proto::sandbox::{HEARTBEAT_VERSION, PATH_SANDBOX_STATE, SandboxHeartbeat, SandboxLink};

use crate::audit::StoreEpoch;
use crate::error::{ClientError, ClientResult};

/// How far ahead of this device's clock a heartbeat may be signed. Past
/// that, a proxy with its clock ahead would look fresh for longer.
pub const MAX_HEARTBEAT_AHEAD_MS: i64 = 5 * 60 * 1000;

/// A heartbeat that counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heartbeat {
    /// The epoch it was sent under: the proxy's current one.
    pub store_epoch: Blob,
    /// Its position in the epoch: the caller's new watermark for
    /// `(proxy, store_epoch)`.
    pub seq: u64,
    /// When the proxy signed it (Unix ms).
    pub sent_at_ms: i64,
    /// How old it is by this device's clock (ms, never below 0).
    pub age_ms: i64,
    /// What the proxy says of each sandbox's connection.
    pub sandboxes: Vec<SandboxLink>,
}

/// Why a heartbeat the proxy did sign does not count. The app says the
/// proxy gives no signs; none of these is a sign of tampering on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discarded {
    /// The verified chain has no `sandbox.store_reset` of this proxy, or
    /// the proxy's key was not checked.
    NoEpoch,
    /// It was sent under another epoch than the proxy's last reset in the
    /// chain: from before a new store, or ahead of a reset the device has
    /// not verified yet.
    OtherEpoch,
    /// Signed more than [`MAX_HEARTBEAT_AHEAD_MS`] ahead of this device's
    /// clock.
    Ahead,
    /// A version of the heartbeat this device does not know: a newer proxy.
    /// It counts as no signs until this device is updated, never as
    /// tampering (review of #353, 5).
    Version,
}

fn forged(message: &str) -> ClientError {
    ClientError::Security(format!("proxy heartbeat: {message}"))
}

/// Checks the heartbeat `proof` of `proxy` (spec §13.12).
///
/// - `identity`: the proxy's public identity, as a verified grant vouches
///   for it.
/// - `epochs`: the current epochs from the verify report.
/// - `watermark`: the highest `seq` this device accepted under the
///   proxy's current epoch, if any.
/// - `now_ms`: this device's clock.
///
/// An error is either [`ClientError::Security`] (the proxy did not sign
/// this, or it is not a heartbeat) or [`ClientError::Rollback`] (a `seq`
/// below the watermark: the server sent an older heartbeat than this
/// device saw).
pub fn check_heartbeat(
    proxy: AgentId,
    identity: &PublicIdentity,
    epochs: &[StoreEpoch],
    proof: &AgentProof,
    watermark: Option<u64>,
    now_ms: i64,
) -> ClientResult<Result<Heartbeat, Discarded>> {
    if proof.method != "PUT" || proof.path != PATH_SANDBOX_STATE {
        return Err(forged("signed for another route"));
    }
    let body = proof
        .body
        .as_ref()
        .ok_or_else(|| forged("lacks the body the proxy signed"))?;
    let digest: [u8; 32] = proof
        .body_digest
        .as_bytes()
        .try_into()
        .map_err(|_| forged("bad body digest"))?;
    if agent::body_digest(body.as_bytes()) != digest {
        return Err(forged("body and digest differ"));
    }
    let nonce: [u8; NONCE_LEN] = proof
        .nonce
        .as_bytes()
        .try_into()
        .map_err(|_| forged("bad nonce"))?;
    let signature: [u8; SIGNATURE_LEN] = proof
        .signature
        .as_bytes()
        .try_into()
        .map_err(|_| forged("bad signature"))?;
    let timestamp_ms = u64::try_from(proof.timestamp).map_err(|_| forged("bad time"))?;
    agent::verify_request(
        identity,
        &SignedRequest {
            agent: proxy,
            method: &proof.method,
            path: &proof.path,
            timestamp_ms,
            nonce: &nonce,
            body_digest: &digest,
        },
        &Signature::from_bytes(signature),
    )
    .map_err(|_| forged("the proxy's signature does not verify"))?;
    // The version first: a newer proxy's heartbeat may have fields this
    // device does not know, and that is no sign of tampering.
    #[derive(serde::Deserialize)]
    struct Version {
        v: u32,
    }
    let version: Version =
        serde_json::from_slice(body.as_bytes()).map_err(|_| forged("not a heartbeat"))?;
    if version.v != HEARTBEAT_VERSION {
        return Ok(Err(Discarded::Version));
    }
    let beat: SandboxHeartbeat =
        serde_json::from_slice(body.as_bytes()).map_err(|_| forged("not a heartbeat"))?;
    beat.check_format().map_err(|_| forged("not a heartbeat"))?;
    // The request's own `timestamp` is not compared with `sent_at_ms`: a
    // proxy resumed from a pause sends the heartbeat it kept, signing the
    // request anew. The age comes from `sent_at_ms` alone.
    let Some(current) = epochs.iter().find(|e| e.proxy == proxy) else {
        return Ok(Err(Discarded::NoEpoch));
    };
    if current.store_epoch != beat.store_epoch {
        return Ok(Err(Discarded::OtherEpoch));
    }
    if beat.sent_at_ms.saturating_sub(now_ms) > MAX_HEARTBEAT_AHEAD_MS {
        return Ok(Err(Discarded::Ahead));
    }
    if let Some(seen) = watermark
        && beat.seq < seen
    {
        return Err(ClientError::Rollback(format!(
            "heartbeat {} of proxy {proxy}, after {seen}",
            beat.seq
        )));
    }
    Ok(Ok(Heartbeat {
        store_epoch: beat.store_epoch,
        seq: beat.seq,
        sent_at_ms: beat.sent_at_ms,
        age_ms: now_ms.saturating_sub(beat.sent_at_ms).max(0),
        sandboxes: beat.sandboxes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use klav_core::crypto::identity::IdentityKeyPair;
    use klav_core::ids::SandboxId;

    const NOW: i64 = 1_800_000_000_000;

    struct Proxy {
        id: AgentId,
        keys: IdentityKeyPair,
        epoch: Blob,
    }

    impl Proxy {
        fn new() -> Self {
            Self {
                id: AgentId::generate(),
                keys: IdentityKeyPair::generate(),
                epoch: Blob::new(vec![5; 16]),
            }
        }

        fn epochs(&self) -> Vec<StoreEpoch> {
            vec![StoreEpoch {
                proxy: self.id,
                store_epoch: self.epoch.clone(),
                seq: 7,
            }]
        }

        fn sign(&self, method: &str, path: &str, body: &[u8], timestamp: i64) -> AgentProof {
            let nonce = [3u8; NONCE_LEN];
            let digest = agent::body_digest(body);
            let signature = agent::sign_request(
                &self.keys,
                &SignedRequest {
                    agent: self.id,
                    method,
                    path,
                    timestamp_ms: u64::try_from(timestamp).unwrap(),
                    nonce: &nonce,
                    body_digest: &digest,
                },
            );
            AgentProof {
                method: method.into(),
                path: path.into(),
                timestamp,
                nonce: Blob::new(nonce.to_vec()),
                body_digest: Blob::new(digest.to_vec()),
                body: Some(Blob::new(body.to_vec())),
                signature: Blob::new(signature.to_bytes().to_vec()),
            }
        }

        fn beat(&self, seq: u64, sent_at_ms: i64) -> AgentProof {
            self.beat_in(&self.epoch, seq, sent_at_ms)
        }

        fn beat_in(&self, epoch: &Blob, seq: u64, sent_at_ms: i64) -> AgentProof {
            let body = serde_json::to_vec(&SandboxHeartbeat {
                v: HEARTBEAT_VERSION,
                store_epoch: epoch.clone(),
                seq,
                sent_at_ms,
                sandboxes: vec![SandboxLink {
                    id: SandboxId::generate(),
                    connected: true,
                    last_seen_at: Some(sent_at_ms - 1_000),
                }],
            })
            .unwrap();
            self.sign("PUT", PATH_SANDBOX_STATE, &body, sent_at_ms)
        }

        fn check(
            &self,
            proof: &AgentProof,
            watermark: Option<u64>,
        ) -> ClientResult<Result<Heartbeat, Discarded>> {
            check_heartbeat(
                self.id,
                self.keys.public(),
                &self.epochs(),
                proof,
                watermark,
                NOW,
            )
        }
    }

    fn security(r: ClientResult<Result<Heartbeat, Discarded>>, why: &str) {
        match r {
            Err(ClientError::Security(m)) => assert!(m.contains(why), "{why:?}: {m:?}"),
            other => panic!("expected {why:?}, got {other:?}"),
        }
    }

    #[test]
    fn a_heartbeat_counts_with_its_signed_age() {
        let p = Proxy::new();
        let beat = p.check(&p.beat(4, NOW - 120_000), None).unwrap().unwrap();
        assert_eq!((beat.seq, beat.age_ms), (4, 120_000));
        assert_eq!(beat.store_epoch, p.epoch);
        assert_eq!(beat.sandboxes.len(), 1);
        // The same one again, and a later one, against the watermark.
        assert!(p.check(&p.beat(4, NOW - 120_000), Some(4)).unwrap().is_ok());
        assert!(p.check(&p.beat(5, NOW), Some(4)).unwrap().is_ok());
        // Slightly ahead of this device: counts, as fresh.
        let ahead = p.check(&p.beat(6, NOW + 60_000), Some(5)).unwrap().unwrap();
        assert_eq!(ahead.age_ms, 0);
    }

    /// A server that hands back an older heartbeat than this device saw
    /// under the same epoch is rolling it back (T7, T168).
    #[test]
    fn a_seq_below_the_watermark_is_a_rollback() {
        let p = Proxy::new();
        assert!(matches!(
            p.check(&p.beat(3, NOW), Some(4)),
            Err(ClientError::Rollback(_))
        ));
    }

    #[test]
    fn a_heartbeat_outside_the_current_epoch_or_far_ahead_does_not_count() {
        let p = Proxy::new();
        // From before a new store: the chain's last reset names another.
        let old = p.beat_in(&Blob::new(vec![4; 16]), 9, NOW);
        assert_eq!(p.check(&old, Some(4)).unwrap(), Err(Discarded::OtherEpoch));
        // No reset of this proxy in the chain (or its key not checked).
        let none = check_heartbeat(p.id, p.keys.public(), &[], &p.beat(1, NOW), None, NOW);
        assert_eq!(none.unwrap(), Err(Discarded::NoEpoch));
        // More than 5 minutes ahead of this device.
        let far = NOW + MAX_HEARTBEAT_AHEAD_MS + 1;
        assert_eq!(
            p.check(&p.beat(1, far), None).unwrap(),
            Err(Discarded::Ahead)
        );
    }

    #[test]
    fn a_heartbeat_the_proxy_did_not_sign_fails() {
        let p = Proxy::new();
        // Another key.
        let other = Proxy::new();
        security(
            check_heartbeat(
                p.id,
                other.keys.public(),
                &p.epochs(),
                &p.beat(1, NOW),
                None,
                NOW,
            ),
            "does not verify",
        );
        // A changed body.
        let mut changed = p.beat(1, NOW);
        let mut body: serde_json::Value =
            serde_json::from_slice(changed.body.as_ref().unwrap().as_bytes()).unwrap();
        body["seq"] = 99.into();
        let body = serde_json::to_vec(&body).unwrap();
        changed.body = Some(Blob::new(body.clone()));
        security(p.check(&changed, None), "body and digest differ");
        changed.body_digest = Blob::new(agent::body_digest(&body).to_vec());
        security(p.check(&changed, None), "does not verify");
        // Without its body.
        let mut bare = p.beat(1, NOW);
        bare.body = None;
        security(p.check(&bare, None), "lacks the body");
        // Signed for another route: a store reset is not a heartbeat.
        let reset = p.sign(
            "POST",
            klav_proto::sandbox::PATH_STORE_RESET,
            br#"{"store_epoch":"BQUFBQUFBQUFBQUFBQUFBQ"}"#,
            NOW,
        );
        security(p.check(&reset, None), "another route");
        // Signed, but not a heartbeat.
        let odd = p.sign("PUT", PATH_SANDBOX_STATE, br#"{"v":1}"#, NOW);
        security(p.check(&odd, None), "not a heartbeat");
        let odd = p.sign("PUT", PATH_SANDBOX_STATE, br#"{"seq":1}"#, NOW);
        security(p.check(&odd, None), "not a heartbeat");
    }

    /// A heartbeat of a version this device does not know, from a newer
    /// proxy, counts as no signs, never as tampering; its signature is
    /// still checked (review of #353, 5).
    #[test]
    fn a_heartbeat_of_another_version_is_no_signs() {
        let p = Proxy::new();
        let body = br#"{"v":2,"store_epoch":"BQUFBQUFBQUFBQUFBQUFBQ","seq":1,"new":true}"#;
        let newer = p.sign("PUT", PATH_SANDBOX_STATE, body, NOW);
        assert_eq!(p.check(&newer, Some(9)).unwrap(), Err(Discarded::Version));
        let other = Proxy::new();
        security(
            check_heartbeat(p.id, other.keys.public(), &p.epochs(), &newer, None, NOW),
            "does not verify",
        );
    }

    /// A heartbeat kept through a pause and sent on resume: the request is
    /// signed long after `sent_at_ms`, and it counts, with its real age.
    #[test]
    fn a_heartbeat_sent_after_a_pause_keeps_its_age() {
        let p = Proxy::new();
        let mut beat = p.beat(3, NOW - 3_600_000);
        let body = beat.body.take().unwrap();
        let resent = p.sign("PUT", PATH_SANDBOX_STATE, body.as_bytes(), NOW);
        let checked = p.check(&resent, Some(2)).unwrap().unwrap();
        assert_eq!(checked.age_ms, 3_600_000);
    }

    /// The vector in `docs/vectores/sandbox-heartbeat.json` checks here.
    #[test]
    fn the_heartbeat_vector_checks() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/vectores/sandbox-heartbeat.json"
        ))
        .unwrap();
        let file: serde_json::Value = serde_json::from_str(&text).unwrap();
        let case = &file["cases"][1];
        let hex = |key: &str| {
            data_encoding::HEXLOWER
                .decode(case[key].as_str().unwrap().as_bytes())
                .unwrap()
        };
        let proxy = AgentId::from_bytes(hex("proxy_agent_id").try_into().unwrap());
        let identity = PublicIdentity::decode(&hex("proxy_public_identity")).unwrap();
        let body = case["body"].as_str().unwrap().as_bytes().to_vec();
        let beat: SandboxHeartbeat = serde_json::from_slice(&body).unwrap();
        let proof = AgentProof {
            method: case["method"].as_str().unwrap().into(),
            path: case["path"].as_str().unwrap().into(),
            timestamp: case["timestamp_ms"].as_i64().unwrap(),
            nonce: Blob::new(hex("nonce")),
            body_digest: Blob::new(hex("body_sha256")),
            body: Some(Blob::new(body)),
            signature: Blob::new(hex("request_signature")),
        };
        let epochs = [StoreEpoch {
            proxy,
            store_epoch: beat.store_epoch.clone(),
            seq: 1,
        }];
        let now = beat.sent_at_ms + 60_000;
        let checked = check_heartbeat(proxy, &identity, &epochs, &proof, None, now)
            .unwrap()
            .unwrap();
        assert_eq!((checked.seq, checked.age_ms), (1, 60_000));
        assert_eq!(checked.sandboxes, beat.sandboxes);
    }
}
