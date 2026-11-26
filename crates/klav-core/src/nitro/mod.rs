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
//! * [`verify_handoff_holder`]: what a joining enclave checks of the holder
//!   (§4.2 step 3).
//! * [`derive_account_keys`], [`enclave_binding`], [`handoff_info`],
//!   [`sign_enroll`]: the per-account keys and the labels (§3.1, §4.2, §6.1).
//! * [`seal_handoff`] and [`open_handoff`] (kind `0x28`): the seed and the
//!   enclave's state, sealed to a verified peer (§4.2 step 4).
//! * [`hosted_service_keys`] and [`sign_hosted_registration`]: the mark on a
//!   hosted agent's registration (§8).
//! * [`fake`], only with the feature `nitro-testkit`: a fake NSM with a test
//!   P-384 chain, for tests of other crates. Never in a release build.

#[cfg(all(feature = "nitro-testkit", not(debug_assertions)))]
compile_error!("`nitro-testkit` is for tests only: it must never be in a release build");

mod attestation;
mod cbor;
mod chain;
mod error;
mod hosted;
mod manifest;

#[cfg(any(test, feature = "nitro-testkit"))]
pub mod fake;
#[cfg(any(test, feature = "nitro-testkit"))]
mod testkit;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod vectors;

pub use attestation::{
    COSE_SIGN1_TAG, FRESHNESS_MS, HandoffHolder, HandoffPeer, HostedProxyExpectation,
    MAX_DOCUMENT_LEN, MAX_OPTIONAL_FIELD_LEN, Measurement, PCR_COUNT, PCR_LEN, PROTECTED_ES384,
    Pcr, SIGNATURE_LEN, VerifiedDocument, verify_document, verify_handoff_holder,
    verify_handoff_peer, verify_hosted_proxy,
};
pub use chain::{AWS_NITRO_ROOT_G1, AWS_NITRO_ROOT_G1_SHA256, MAX_CERTIFICATE_LEN, MAX_CHAIN};
pub use error::{CborError, NitroError};
pub use hosted::{
    HANDOFF_OVERHEAD, HandoffKey, HostedSeed, LABEL_ENCLAVE_BINDING, LABEL_ENCLAVE_HANDOFF,
    LABEL_HOSTED_ACCOUNT, LABEL_HOSTED_PROXY_ENROLL, LABEL_HOSTED_PROXY_REGISTRATION,
    LABEL_HOSTED_SEED, LABEL_HOSTED_SERVICE, MAX_HANDOFF_STATE, SEED_LEN, derive_account_keys,
    enclave_binding, handoff_info, hosted_account_info, hosted_service_keys, open_handoff,
    seal_handoff, sign_enroll, sign_hosted_registration, verify_enroll, verify_hosted_registration,
};
pub use manifest::{
    ImageStatus, LABEL_ENCLAVE_MANIFEST, MANIFEST_CLOCK_SKEW_MS, MANIFEST_VERSION, MAX_EGRESS,
    MAX_MANIFEST_LEN, MAX_MANIFEST_LIFETIME_MS, ManifestImage, RELEASE_AUTHORITY_KEYS,
    VerifiedManifest, manifest_message, verify_manifest,
};
