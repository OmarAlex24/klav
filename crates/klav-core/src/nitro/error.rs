//! Errors of the Nitro attestation and enclave manifest checks.
//!
//! Every refusal has its own variant and a stable [`NitroError::code`], so a
//! test or a vector names the exact check that failed. None of them carries
//! key material: the documents and manifests are public.

use thiserror::Error;

/// Why the strict CBOR reader refused its input (spec §15.2).
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CborError {
    /// The input ends inside an item, or a count is larger than the input.
    #[error("truncated")]
    Truncated,
    /// Bytes left after the top-level item.
    #[error("trailing bytes")]
    TrailingBytes,
    /// An indefinite length or a `break` byte.
    #[error("indefinite length")]
    IndefiniteLength,
    /// A length or an integer not in its shortest form.
    #[error("non-canonical length or integer")]
    NonCanonical,
    /// A map key repeated in the same map.
    #[error("duplicate map key")]
    DuplicateKey,
    /// A map key that is not an integer or a text string.
    #[error("map key of an unsupported type")]
    MapKeyType,
    /// A float, `undefined` or a simple value other than `false`, `true`, `null`.
    #[error("unsupported simple value or float")]
    Unsupported,
    /// Additional information 28–30 (reserved by RFC 8949).
    #[error("reserved additional information")]
    Reserved,
    /// A text string that is not UTF-8.
    #[error("text is not UTF-8")]
    InvalidUtf8,
    /// Nesting deeper than the reader allows.
    #[error("nesting too deep")]
    TooDeep,
}

/// Why an attestation document, an enclave or a manifest was refused
/// (spec §15, ADR 0051 §2.2 and §2.4).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NitroError {
    /// The document is larger than 16 KiB.
    #[error("attestation document too large")]
    TooLarge,
    /// The bytes are not strict CBOR.
    #[error("attestation document is not strict CBOR: {0}")]
    Cbor(#[from] CborError),
    /// Not a `COSE_Sign1` (a 4-element array, optionally under tag 18).
    #[error("not a COSE_Sign1 structure: {0}")]
    Cose(&'static str),
    /// The protected header is not exactly `{1: -35}` (ES384).
    #[error("COSE protected header is not ES384 only")]
    ProtectedHeader,
    /// The unprotected header is not an empty map.
    #[error("COSE unprotected header is not empty")]
    UnprotectedHeader,
    /// The payload map has a key the format does not define.
    #[error("unknown field in the attestation payload")]
    UnknownField,
    /// A field of the payload is missing or of the wrong type or size.
    #[error("attestation payload field {0} is missing or malformed")]
    Field(&'static str),
    /// `digest` is not `"SHA384"`.
    #[error("attestation digest is not SHA384")]
    Digest,
    /// More certificates than allowed, or none in `cabundle`.
    #[error("certificate chain has the wrong length")]
    ChainLength,
    /// `cabundle[0]` is not the pinned AWS Nitro Enclaves root.
    #[error("the chain does not start at the pinned root")]
    RootMismatch,
    /// A certificate is not DER, not X.509 v3, or not shaped as expected.
    #[error("certificate {index} is malformed: {reason}")]
    Certificate {
        /// Position in the chain, root first, leaf last.
        index: usize,
        /// What is wrong.
        reason: &'static str,
    },
    /// A certificate or its key is not ECDSA P-384 with SHA-384.
    #[error("certificate {index} does not use ECDSA P-384 with SHA-384")]
    Algorithm {
        /// Position in the chain, root first, leaf last.
        index: usize,
    },
    /// A certificate is outside its validity period at the device's clock.
    #[error("certificate {index} is not valid at this time")]
    Validity {
        /// Position in the chain, root first, leaf last.
        index: usize,
    },
    /// A certificate's issuer is not the subject of the one before it.
    #[error("certificate {index} was not issued by the certificate before it")]
    IssuerMismatch {
        /// Position in the chain, root first, leaf last.
        index: usize,
    },
    /// A certificate of `cabundle` is not a CA, or may not sign certificates.
    #[error("certificate {index} is not a CA")]
    NotCa {
        /// Position in the chain, root first, leaf last.
        index: usize,
    },
    /// The leaf certificate is a CA or may not sign.
    #[error("the leaf certificate is a CA or may not sign")]
    LeafUsage,
    /// A CA's `pathLenConstraint` is exceeded.
    #[error("certificate {index} has a path length constraint the chain exceeds")]
    PathLength {
        /// Position in the chain, root first, leaf last.
        index: usize,
    },
    /// A critical extension Klav does not process, or an extension twice.
    #[error("certificate {index} has an unsupported critical or repeated extension")]
    Extension {
        /// Position in the chain, root first, leaf last.
        index: usize,
    },
    /// A certificate's signature does not verify with its issuer's key.
    #[error("certificate {index} has an invalid signature")]
    ChainSignature {
        /// Position in the chain, root first, leaf last.
        index: usize,
    },
    /// The COSE signature does not verify with the leaf's key.
    #[error("the attestation signature is invalid")]
    Signature,
    /// `module_id` is empty.
    #[error("module_id is empty")]
    ModuleId,
    /// PCR0, PCR1 or PCR2 is all zeros: a debug-mode enclave.
    #[error("the enclave runs in debug mode (zero PCRs)")]
    DebugEnclave,
    /// `timestamp` is more than 5 minutes from the device's clock.
    #[error("the attestation is not fresh")]
    Stale,
    /// `nonce` is missing or is not the one the device sent.
    #[error("the attestation nonce does not match")]
    Nonce,
    /// `user_data` is missing or is not the expected binding.
    #[error("the attestation does not bind the expected keys")]
    Binding,
    /// `public_key` is missing or is not a 32-byte X25519 key (hand-off).
    #[error("the attestation has no hand-off key")]
    PublicKey,
    /// PCR0–2 match no image of the manifest.
    #[error("the enclave image is not in the manifest")]
    ImageNotListed,
    /// The image is listed as revoked.
    #[error("the enclave image is revoked")]
    ImageRevoked,
    /// PCR3 is not one of the manifest's `parent_roles` (hand-off).
    #[error("the enclave runs on an instance role the manifest does not list")]
    ParentRole,
    /// The peer's image is older than the holder's (hand-off).
    #[error("the peer runs an older image")]
    Downgrade,
    /// No release-authority key is pinned in this build.
    #[error("no release authority key is pinned in this build")]
    NoReleaseKey,
    /// The manifest's signature does not verify with any pinned key.
    #[error("the enclave manifest signature is invalid")]
    ManifestSignature,
    /// The manifest is not valid JSON of version 1, or breaks a rule.
    #[error("the enclave manifest is malformed: {0}")]
    ManifestMalformed(&'static str),
    /// The manifest's `seq` is lower than the highest one this device saw.
    #[error("the enclave manifest is older than one already seen")]
    ManifestRollback,
    /// The manifest is past `expires_at_ms`.
    #[error("the enclave manifest has expired")]
    ManifestExpired,
    /// The manifest's `issued_at_ms` is in the future.
    #[error("the enclave manifest is issued in the future")]
    ManifestFuture,
}

impl NitroError {
    /// A stable name for the check that failed, used by the test vectors.
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::Cbor(e) => match e {
                CborError::Truncated => "cbor_truncated",
                CborError::TrailingBytes => "cbor_trailing_bytes",
                CborError::IndefiniteLength => "cbor_indefinite_length",
                CborError::NonCanonical => "cbor_non_canonical",
                CborError::DuplicateKey => "cbor_duplicate_key",
                CborError::MapKeyType => "cbor_map_key_type",
                CborError::Unsupported => "cbor_unsupported",
                CborError::Reserved => "cbor_reserved",
                CborError::InvalidUtf8 => "cbor_invalid_utf8",
                CborError::TooDeep => "cbor_too_deep",
            },
            Self::Cose(_) => "cose",
            Self::ProtectedHeader => "protected_header",
            Self::UnprotectedHeader => "unprotected_header",
            Self::UnknownField => "unknown_field",
            Self::Field(_) => "field",
            Self::Digest => "digest",
            Self::ChainLength => "chain_length",
            Self::RootMismatch => "root_mismatch",
            Self::Certificate { .. } => "certificate",
            Self::Algorithm { .. } => "algorithm",
            Self::Validity { .. } => "validity",
            Self::IssuerMismatch { .. } => "issuer_mismatch",
            Self::NotCa { .. } => "not_ca",
            Self::LeafUsage => "leaf_usage",
            Self::PathLength { .. } => "path_length",
            Self::Extension { .. } => "extension",
            Self::ChainSignature { .. } => "chain_signature",
            Self::Signature => "signature",
            Self::ModuleId => "module_id",
            Self::DebugEnclave => "debug_enclave",
            Self::Stale => "stale",
            Self::Nonce => "nonce",
            Self::Binding => "binding",
            Self::PublicKey => "public_key",
            Self::ImageNotListed => "image_not_listed",
            Self::ImageRevoked => "image_revoked",
            Self::ParentRole => "parent_role",
            Self::Downgrade => "downgrade",
            Self::NoReleaseKey => "no_release_key",
            Self::ManifestSignature => "manifest_signature",
            Self::ManifestMalformed(_) => "manifest_malformed",
            Self::ManifestRollback => "manifest_rollback",
            Self::ManifestExpired => "manifest_expired",
            Self::ManifestFuture => "manifest_future",
        }
    }
}
