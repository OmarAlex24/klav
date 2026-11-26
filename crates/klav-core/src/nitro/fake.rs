//! A fake NSM and release authority for the tests of other crates (feature
//! `nitro-testkit`, ADR 0051 layer 3): `klav-proxy`'s enclave tests run on
//! any machine, without Nitro hardware, against a test P-384 chain built at
//! the test's clock.
//!
//! **Nothing here is trusted by a real check.** The production verifiers
//! ([`super::verify_hosted_proxy`], [`super::verify_handoff_peer`],
//! [`super::verify_handoff_holder`], [`super::verify_manifest`]) take only
//! the pinned AWS root and [`super::RELEASE_AUTHORITY_KEYS`]; the `*_with_*`
//! functions below, which accept the test anchors, exist only with this
//! feature, and the feature refuses to compile in a release build.

use ed25519_dalek::Signer as _;

use super::NitroError;
use super::attestation::{
    HandoffHolder, HandoffPeer, HostedProxyExpectation, Pcr, VerifiedDocument,
    verify_document_with_root, verify_handoff_holder_with_root, verify_handoff_peer_with_root,
    verify_hosted_proxy_with_root,
};
use super::manifest::{
    ManifestImage, VerifiedManifest, manifest_message, verify_manifest_with_keys,
};
use super::testkit::{CertSpec, DocSpec, TestChain, det, p384_key};

const HOUR_MS: u64 = 60 * 60 * 1000;
const DAY_MS: u64 = 24 * HOUR_MS;

/// A fake Nitro Secure Module: a test root, two intermediates and a leaf
/// (ECDSA P-384, AWS's shape), valid around the clock it was made with.
pub struct FakeNitro {
    chain: TestChain,
}

/// What [`FakeNitro::attest`] puts in a document.
#[derive(Debug, Clone, Copy)]
pub struct FakeAttestation<'a> {
    /// PCR0 to PCR3 (PCR4 to PCR15 are zero).
    pub pcrs: &'a [Pcr; 4],
    /// The document's `timestamp`.
    pub timestamp_ms: u64,
    /// `public_key`, if any.
    pub public_key: Option<&'a [u8]>,
    /// `user_data`, if any.
    pub user_data: Option<&'a [u8]>,
    /// `nonce`, if any.
    pub nonce: Option<&'a [u8]>,
}

impl FakeNitro {
    /// A chain valid from 30 days before `now_ms` to 30 days after (the
    /// leaf: one hour before to seven days after). `label` picks its keys:
    /// two fakes with different labels are two unrelated roots.
    pub fn new(label: &str, now_ms: u64) -> Self {
        let mut specs = TestChain::specs();
        let last = specs.len() - 1;
        for (i, spec) in specs.iter_mut().enumerate() {
            spec.subject = format!("{label}.{}", spec.subject);
            spec.issuer = format!("{label}.{}", spec.issuer);
            if i == last {
                spec.not_before_ms = now_ms - HOUR_MS;
                spec.not_after_ms = now_ms + 7 * DAY_MS;
            } else {
                spec.not_before_ms = now_ms - 30 * DAY_MS;
                spec.not_after_ms = now_ms + 30 * DAY_MS;
            }
        }
        Self {
            chain: chain_with(label, specs),
        }
    }

    /// The root a test verifier pins instead of AWS's.
    pub fn root(&self) -> &[u8] {
        &self.chain.root
    }

    /// A signed attestation document, untagged like the NSM's.
    pub fn attest(&self, what: &FakeAttestation<'_>) -> Vec<u8> {
        let mut spec = DocSpec::new(b"", b"");
        spec.module_id = "i-0fa4e0000000000000-enc0fa4e000000000000".into();
        spec.timestamp_ms = what.timestamp_ms;
        for (i, pcr) in what.pcrs.iter().enumerate() {
            spec.set_pcr(i as u64, pcr);
        }
        spec.public_key = what.public_key.map(<[u8]>::to_vec);
        spec.user_data = what.user_data.map(<[u8]>::to_vec);
        spec.nonce = what.nonce.map(<[u8]>::to_vec);
        spec.build(&self.chain)
    }
}

/// [`TestChain::from_specs`] with keys of its own label.
fn chain_with(label: &str, specs: Vec<CertSpec>) -> TestChain {
    let keys: Vec<_> = (0..specs.len())
        .map(|i| p384_key(&format!("{label} chain key {i}")))
        .collect();
    let certs: Vec<Vec<u8>> = specs
        .iter()
        .enumerate()
        .map(|(i, spec)| spec.build(&keys[i], &keys[i.saturating_sub(1)]))
        .collect();
    let (leaf, cas) = certs.split_last().expect("at least a root and a leaf");
    TestChain {
        root: cas[0].clone(),
        intermediates: cas[1..].to_vec(),
        leaf: leaf.clone(),
        leaf_key: keys[keys.len() - 1].clone(),
        specs,
        keys,
    }
}

/// Deterministic PCR0 to PCR3 of a test image named `label`.
pub fn test_pcrs(label: &str) -> [Pcr; 4] {
    [0, 1, 2, 3].map(|i| det(&format!("{label} pcr {i}")))
}

/// A test release-authority key (Ed25519).
pub struct FakeReleaseKey(ed25519_dalek::SigningKey);

impl FakeReleaseKey {
    /// The key named `label`.
    pub fn new(label: &str) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&det(&format!(
            "fake release key {label}"
        ))))
    }

    /// Its public half, as [`super::RELEASE_AUTHORITY_KEYS`] holds them.
    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Signs `manifest` as the release authority does.
    pub fn sign(&self, manifest: &[u8]) -> [u8; 64] {
        self.0.sign(&manifest_message(manifest)).to_bytes()
    }
}

/// [`super::verify_document`] against `root`.
pub fn verify_document_with(
    document: &[u8],
    root: &[u8],
    now_ms: u64,
) -> Result<VerifiedDocument, NitroError> {
    verify_document_with_root(document, root, now_ms)
}

/// [`super::verify_manifest`] against `keys`.
pub fn verify_manifest_with(
    manifest: &[u8],
    signature: &[u8; 64],
    keys: &[[u8; 32]],
    highest_seq: Option<u64>,
    now_ms: u64,
) -> Result<VerifiedManifest, NitroError> {
    verify_manifest_with_keys(manifest, signature, keys, highest_seq, now_ms)
}

/// [`super::verify_hosted_proxy`] against `root`.
pub fn verify_hosted_proxy_with<'m>(
    document: &[u8],
    root: &[u8],
    manifest: &'m VerifiedManifest,
    expected: &HostedProxyExpectation<'_>,
) -> Result<&'m ManifestImage, NitroError> {
    verify_hosted_proxy_with_root(document, root, manifest, expected)
}

/// [`super::verify_handoff_peer`] against `root`.
pub fn verify_handoff_peer_with<'m>(
    document: &[u8],
    root: &[u8],
    manifest: &'m VerifiedManifest,
    own: &ManifestImage,
    nonce: &[u8],
    now_ms: u64,
) -> Result<HandoffPeer<'m>, NitroError> {
    verify_handoff_peer_with_root(document, root, manifest, own, nonce, now_ms)
}

/// [`super::verify_handoff_holder`] against `root`.
pub fn verify_handoff_holder_with<'m>(
    document: &[u8],
    root: &[u8],
    manifest: &'m VerifiedManifest,
    nonce: &[u8],
    now_ms: u64,
) -> Result<HandoffHolder<'m>, NitroError> {
    verify_handoff_holder_with_root(document, root, manifest, nonce, now_ms)
}

/// The seed's bytes, for a test that checks they appear in no log.
pub fn seed_bytes(seed: &super::HostedSeed) -> zeroize::Zeroizing<[u8; 32]> {
    zeroize::Zeroizing::new(*seed.expose())
}

/// A key pair's two private keys (X25519 ‖ Ed25519 seed), for a test that
/// checks they appear in no log.
pub fn secret_bytes(
    keys: &crate::crypto::identity::IdentityKeyPair,
) -> zeroize::Zeroizing<[u8; 64]> {
    keys.secrets_plaintext()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    #[test]
    fn a_fake_document_verifies_against_its_own_root_only() {
        let nitro = FakeNitro::new("one", NOW);
        let other = FakeNitro::new("two", NOW);
        let pcrs = test_pcrs("image");
        let doc = nitro.attest(&FakeAttestation {
            pcrs: &pcrs,
            timestamp_ms: NOW,
            public_key: Some(&[7; 32]),
            user_data: Some(b"binding"),
            nonce: Some(b"nonce"),
        });
        let verified = verify_document_with(&doc, nitro.root(), NOW).expect("verifies");
        assert_eq!(verified.pcr(3), Some(&pcrs[3]));
        assert_eq!(verified.public_key(), Some(&[7u8; 32][..]));
        assert_eq!(
            verify_document_with(&doc, other.root(), NOW)
                .err()
                .map(|e| e.code()),
            Some("root_mismatch")
        );
        // The leaf lapses a week after the clock it was made with.
        assert_eq!(
            verify_document_with(&doc, nitro.root(), NOW + 8 * DAY_MS)
                .err()
                .map(|e| e.code()),
            Some("validity")
        );
    }
}
