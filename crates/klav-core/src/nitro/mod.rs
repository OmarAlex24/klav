//! Klav Cloud's hosted proxy: what a device verifies before it wraps any
//! credential for it, and the keys the enclave derives (ADR 0051, spec §15).
//!
//! Behind the non-default feature `nitro-attestation`. `klav-wasm` never
//! turns it on: the extension never wraps for a proxy.
//!
//! * [`verify_document`]: strict CBOR and `COSE_Sign1` decoding, the chain
//!   to the pinned AWS Nitro Enclaves Root-G1 ([`AWS_NITRO_ROOT_G1`]), and
//!   the ES384 signature (ADR 0051 §2.2 steps 2–4).
//! * [`verify_hosted_proxy`]: those steps plus the nonce, freshness, the
//!   binding in `user_data`, nonzero PCRs and the manifest (steps 2–6).
//! * [`verify_handoff_peer`]: what an enclave checks of a peer before it
//!   hands over the seed (§4.2).
//! * [`verify_manifest`]: the signed Klav Enclave Transparency Manifest
//!   (§2.4), against [`RELEASE_AUTHORITY_KEYS`], which this build leaves
//!   empty: every manifest is refused until a later layer pins the keys.
//! * [`derive_account_keys`], [`enclave_binding`], [`handoff_info`],
//!   [`sign_enroll`]: the per-account keys and the labels (§3.1, §4.2, §6.1).

mod attestation;
mod cbor;
mod chain;
mod error;
mod hosted;
mod manifest;

#[cfg(test)]
mod testkit;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod vectors;

pub use attestation::{
    COSE_SIGN1_TAG, FRESHNESS_MS, HandoffPeer, HostedProxyExpectation, MAX_DOCUMENT_LEN,
    MAX_OPTIONAL_FIELD_LEN, Measurement, PCR_COUNT, PCR_LEN, PROTECTED_ES384, Pcr, SIGNATURE_LEN,
    VerifiedDocument, verify_document, verify_handoff_peer, verify_hosted_proxy,
};
pub use chain::{AWS_NITRO_ROOT_G1, AWS_NITRO_ROOT_G1_SHA256, MAX_CERTIFICATE_LEN, MAX_CHAIN};
pub use error::{CborError, NitroError};
pub use hosted::{
    HostedSeed, LABEL_ENCLAVE_BINDING, LABEL_ENCLAVE_HANDOFF, LABEL_HOSTED_ACCOUNT,
    LABEL_HOSTED_PROXY_ENROLL, SEED_LEN, derive_account_keys, enclave_binding, handoff_info,
    hosted_account_info, sign_enroll, verify_enroll,
};
pub use manifest::{
    ImageStatus, LABEL_ENCLAVE_MANIFEST, MANIFEST_CLOCK_SKEW_MS, MANIFEST_VERSION, MAX_EGRESS,
    MAX_MANIFEST_LEN, MAX_MANIFEST_LIFETIME_MS, ManifestImage, RELEASE_AUTHORITY_KEYS,
    VerifiedManifest, manifest_message, verify_manifest,
};
