//! The AWS Nitro Enclaves attestation document: strict decoding, the
//! `COSE_Sign1` ES384 signature, and the checks a device runs before it
//! wraps anything for Klav Cloud's hosted proxy (spec §15.2–§15.4, ADR 0051
//! §2.2 and §4.2).

use std::collections::BTreeMap;

use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};

use super::NitroError;
use super::cbor::{self, Value};
use super::chain;
use super::manifest::{ManifestImage, VerifiedManifest};

/// Largest document accepted, in bytes.
pub const MAX_DOCUMENT_LEN: usize = 16 * 1024;
/// Largest `public_key`, `user_data` or `nonce`, in bytes (AWS's limit).
pub const MAX_OPTIONAL_FIELD_LEN: usize = 1024;
/// Length of a PCR with `digest = "SHA384"`.
pub const PCR_LEN: usize = 48;
/// Highest PCR index plus one (the NSM has 32 PCRs; documents carry 16).
pub const PCR_COUNT: u64 = 32;
/// How far `timestamp` may be from the device's clock, either way.
pub const FRESHNESS_MS: u64 = 5 * 60 * 1000;
/// Length of the ES384 signature `r ‖ s`.
pub const SIGNATURE_LEN: usize = 96;
/// The protected header the NSM writes: the CBOR map `{1: -35}` (alg ES384).
/// Any encoding of that one-entry map is accepted, such as the indefinite
/// `bf 01 38 22 ff` (spec §15.2); the signature covers the bytes as sent.
pub const PROTECTED_ES384: [u8; 4] = [0xa1, 0x01, 0x38, 0x22];
/// CBOR tag of a `COSE_Sign1` (RFC 9052). The NSM omits it; AWS's
/// documentation shows it, so both are accepted.
pub const COSE_SIGN1_TAG: u64 = 18;

/// A PCR value.
pub type Pcr = [u8; PCR_LEN];

/// PCR0, PCR1 and PCR2 of an enclave: its image, kernel and application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measurement {
    /// PCR0: the enclave image file.
    pub pcr0: Pcr,
    /// PCR1: the kernel and boot ramfs.
    pub pcr1: Pcr,
    /// PCR2: the application.
    pub pcr2: Pcr,
}

/// An attestation document whose chain and signature verified. Its fields
/// are what AWS's PKI vouches for; none of them is checked against what the
/// device expects until [`verify_hosted_proxy`] or [`verify_handoff_peer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDocument {
    module_id: String,
    timestamp_ms: u64,
    pcrs: BTreeMap<u8, Pcr>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

impl VerifiedDocument {
    /// The enclave's `module_id`.
    pub fn module_id(&self) -> &str {
        &self.module_id
    }

    /// When the NSM signed the document, in Unix milliseconds.
    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    /// PCR `index`, if the document has it.
    pub fn pcr(&self, index: u8) -> Option<&Pcr> {
        self.pcrs.get(&index)
    }

    /// `public_key`, if present.
    pub fn public_key(&self) -> Option<&[u8]> {
        self.public_key.as_deref()
    }

    /// `user_data`, if present.
    pub fn user_data(&self) -> Option<&[u8]> {
        self.user_data.as_deref()
    }

    /// `nonce`, if present.
    pub fn nonce(&self) -> Option<&[u8]> {
        self.nonce.as_deref()
    }

    /// PCR0–2, refusing a debug-mode enclave (any of them all zeros).
    pub fn measurement(&self) -> Result<Measurement, NitroError> {
        let get = |i| self.pcrs.get(&i).copied().ok_or(NitroError::Field("pcrs"));
        let m = Measurement {
            pcr0: get(0)?,
            pcr1: get(1)?,
            pcr2: get(2)?,
        };
        if [m.pcr0, m.pcr1, m.pcr2]
            .iter()
            .any(|p| p.iter().all(|b| *b == 0))
        {
            return Err(NitroError::DebugEnclave);
        }
        Ok(m)
    }

    fn check_fresh(&self, nonce: &[u8], now_ms: u64) -> Result<(), NitroError> {
        if self.nonce.as_deref() != Some(nonce) {
            return Err(NitroError::Nonce);
        }
        if self.timestamp_ms.abs_diff(now_ms) > FRESHNESS_MS {
            return Err(NitroError::Stale);
        }
        Ok(())
    }
}

/// Steps 2–4 of ADR 0051 §2.2: strict decoding, the chain to the pinned AWS
/// Nitro Enclaves Root-G1 at `now_ms`, and the ES384 signature.
pub fn verify_document(document: &[u8], now_ms: u64) -> Result<VerifiedDocument, NitroError> {
    verify_document_with_root(document, chain::AWS_NITRO_ROOT_G1, now_ms)
}

/// [`verify_document`] against another root: only the tests' synthetic
/// chains use it.
pub(crate) fn verify_document_with_root(
    document: &[u8],
    root: &[u8],
    now_ms: u64,
) -> Result<VerifiedDocument, NitroError> {
    if document.len() > MAX_DOCUMENT_LEN {
        return Err(NitroError::TooLarge);
    }
    let cose = match cbor::decode(document)? {
        Value::Tag(COSE_SIGN1_TAG, inner) => *inner,
        Value::Tag(..) => return Err(NitroError::Cose("unexpected tag")),
        other => other,
    };
    let Value::Array(parts) = cose else {
        return Err(NitroError::Cose("not an array"));
    };
    let [protected, unprotected, payload, signature] = parts.as_slice() else {
        return Err(NitroError::Cose("not four elements"));
    };
    let Value::Bytes(protected) = protected else {
        return Err(NitroError::ProtectedHeader);
    };
    check_protected(protected)?;
    if !matches!(unprotected, Value::Map(m) if m.is_empty()) {
        return Err(NitroError::UnprotectedHeader);
    }
    let Value::Bytes(payload) = payload else {
        return Err(NitroError::Cose("payload is not a byte string"));
    };
    let signature = match signature {
        Value::Bytes(s) if s.len() == SIGNATURE_LEN => {
            Signature::from_slice(s).map_err(|_| NitroError::Signature)?
        }
        _ => return Err(NitroError::Cose("signature is not 96 bytes")),
    };

    let fields = Payload::parse(payload)?;
    let leaf_key = chain::verify(root, &fields.cabundle, fields.certificate, now_ms)?;
    verify_signature(&leaf_key, protected, payload, &signature)?;
    Ok(fields.document)
}

/// The protected header must decode, strictly, to exactly `{1: -35}` (alg
/// ES384) and nothing else. Every refusal, including one by the CBOR reader,
/// is [`NitroError::ProtectedHeader`]. The caller signs over the raw bytes.
fn check_protected(protected: &[u8]) -> Result<(), NitroError> {
    match cbor::decode(protected) {
        Ok(Value::Map(entries)) if entries.as_slice() == [(Value::Uint(1), Value::Nint(34))] => {
            Ok(())
        }
        _ => Err(NitroError::ProtectedHeader),
    }
}

/// The COSE `Sig_structure` (RFC 9052 §4.4) for a `COSE_Sign1` with no
/// external AAD: `["Signature1", protected, h'', payload]`.
pub(crate) fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 32);
    out.push(0x84);
    out.push(0x6a);
    out.extend_from_slice(b"Signature1");
    byte_string(&mut out, protected);
    out.push(0x40);
    byte_string(&mut out, payload);
    out
}

fn byte_string(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len() as u64;
    match len {
        0..=23 => out.push(0x40 | len as u8),
        24..=0xff => out.extend_from_slice(&[0x58, len as u8]),
        0x100..=0xffff => {
            out.push(0x59);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            out.push(0x5a);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
    out.extend_from_slice(bytes);
}

fn verify_signature(
    leaf: &VerifyingKey,
    protected: &[u8],
    payload: &[u8],
    signature: &Signature,
) -> Result<(), NitroError> {
    leaf.verify(&sig_structure(protected, payload), signature)
        .map_err(|_| NitroError::Signature)
}

struct Payload<'a> {
    document: VerifiedDocument,
    certificate: &'a [u8],
    cabundle: Vec<&'a [u8]>,
}

impl<'a> Payload<'a> {
    /// The payload map: exactly the keys AWS documents, `public_key`,
    /// `user_data` and `nonce` optional (absent or `null`), nothing else.
    fn parse(payload: &'a [u8]) -> Result<Self, NitroError> {
        let Value::Map(entries) = cbor::decode(payload)? else {
            return Err(NitroError::Field("payload"));
        };
        let mut module_id = None;
        let mut digest = None;
        let mut timestamp = None;
        let mut pcrs = None;
        let mut certificate = None;
        let mut cabundle = None;
        let mut public_key = None;
        let mut user_data = None;
        let mut nonce = None;
        for (key, value) in entries {
            let Value::Text(key) = key else {
                return Err(NitroError::UnknownField);
            };
            match key {
                "module_id" => module_id = Some(value),
                "digest" => digest = Some(value),
                "timestamp" => timestamp = Some(value),
                "pcrs" => pcrs = Some(value),
                "certificate" => certificate = Some(value),
                "cabundle" => cabundle = Some(value),
                "public_key" => public_key = Some(value),
                "user_data" => user_data = Some(value),
                "nonce" => nonce = Some(value),
                _ => return Err(NitroError::UnknownField),
            }
        }

        let module_id = match module_id {
            Some(Value::Text("")) => return Err(NitroError::ModuleId),
            Some(Value::Text(t)) => t.to_owned(),
            _ => return Err(NitroError::Field("module_id")),
        };
        match digest {
            Some(Value::Text("SHA384")) => {}
            Some(Value::Text(_)) => return Err(NitroError::Digest),
            _ => return Err(NitroError::Field("digest")),
        }
        let Some(Value::Uint(timestamp_ms)) = timestamp else {
            return Err(NitroError::Field("timestamp"));
        };
        let Some(Value::Map(pcr_entries)) = pcrs else {
            return Err(NitroError::Field("pcrs"));
        };
        let mut pcrs = BTreeMap::new();
        for (index, value) in pcr_entries {
            match (index, value) {
                (Value::Uint(i), Value::Bytes(v)) if i < PCR_COUNT && v.len() == PCR_LEN => {
                    let mut pcr = [0u8; PCR_LEN];
                    pcr.copy_from_slice(v);
                    pcrs.insert(i as u8, pcr);
                }
                _ => return Err(NitroError::Field("pcrs")),
            }
        }
        if !(0..3).all(|i| pcrs.contains_key(&i)) {
            return Err(NitroError::Field("pcrs"));
        }
        let Some(Value::Bytes(certificate)) = certificate else {
            return Err(NitroError::Field("certificate"));
        };
        let Some(Value::Array(bundle)) = cabundle else {
            return Err(NitroError::Field("cabundle"));
        };
        let cabundle = bundle
            .into_iter()
            .map(|c| match c {
                Value::Bytes(b) => Ok(b),
                _ => Err(NitroError::Field("cabundle")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let optional = |value: Option<Value<'_>>, name| match value {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bytes(b)) if b.len() <= MAX_OPTIONAL_FIELD_LEN => Ok(Some(b.to_vec())),
            _ => Err(NitroError::Field(name)),
        };
        Ok(Self {
            document: VerifiedDocument {
                module_id,
                timestamp_ms,
                pcrs,
                public_key: optional(public_key, "public_key")?,
                user_data: optional(user_data, "user_data")?,
                nonce: optional(nonce, "nonce")?,
            },
            certificate,
            cabundle,
        })
    }
}

/// What a device expects of the hosted proxy's attestation for one account.
#[derive(Debug, Clone, Copy)]
pub struct HostedProxyExpectation<'a> {
    /// The nonce the device sent with `GET /v1/attest`.
    pub nonce: &'a [u8],
    /// [`super::enclave_binding`] of the agent the server shows for the
    /// account's hosted proxy.
    pub binding: &'a [u8; 32],
    /// The device's clock, Unix milliseconds.
    pub now_ms: u64,
}

/// Steps 2–6 of ADR 0051 §2.2: the whole check a device runs before it wraps
/// an item key for the hosted proxy, approves its registration or sets
/// `proxy.mode = "klav"`. Returns the manifest's entry for the image, whose
/// status is `current` or `draining`.
pub fn verify_hosted_proxy<'m>(
    document: &[u8],
    manifest: &'m VerifiedManifest,
    expected: &HostedProxyExpectation<'_>,
) -> Result<&'m ManifestImage, NitroError> {
    verify_hosted_proxy_with_root(document, chain::AWS_NITRO_ROOT_G1, manifest, expected)
}

pub(crate) fn verify_hosted_proxy_with_root<'m>(
    document: &[u8],
    root: &[u8],
    manifest: &'m VerifiedManifest,
    expected: &HostedProxyExpectation<'_>,
) -> Result<&'m ManifestImage, NitroError> {
    let doc = verify_document_with_root(document, root, expected.now_ms)?;
    doc.check_fresh(expected.nonce, expected.now_ms)?;
    if doc.user_data.as_deref() != Some(expected.binding.as_slice()) {
        return Err(NitroError::Binding);
    }
    manifest.image_for(&doc.measurement()?)
}

/// A joining enclave that passed [`verify_handoff_peer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffPeer<'m> {
    /// Its image in the manifest.
    pub image: &'m ManifestImage,
    /// Its PCRs.
    pub measurement: Measurement,
    /// The X25519 key it attested in `public_key`, to seal the seed to.
    pub x25519: [u8; 32],
}

/// ADR 0051 §4.2 step 2: what an enclave holding the seed checks of a peer
/// before handing it over. Steps 2–4 and 6 of §2.2, plus: `nonce` is the
/// holder's, PCR3 is one of the manifest's `parent_roles`, the peer's image
/// is not older than `own`, and `public_key` is a 32-byte X25519 key. That
/// the manifest is the one published in the repository is the caller's
/// check (§4.2).
pub fn verify_handoff_peer<'m>(
    document: &[u8],
    manifest: &'m VerifiedManifest,
    own: &ManifestImage,
    nonce: &[u8],
    now_ms: u64,
) -> Result<HandoffPeer<'m>, NitroError> {
    verify_handoff_peer_with_root(
        document,
        chain::AWS_NITRO_ROOT_G1,
        manifest,
        own,
        nonce,
        now_ms,
    )
}

pub(crate) fn verify_handoff_peer_with_root<'m>(
    document: &[u8],
    root: &[u8],
    manifest: &'m VerifiedManifest,
    own: &ManifestImage,
    nonce: &[u8],
    now_ms: u64,
) -> Result<HandoffPeer<'m>, NitroError> {
    let doc = verify_document_with_root(document, root, now_ms)?;
    doc.check_fresh(nonce, now_ms)?;
    let measurement = doc.measurement()?;
    let image = manifest.image_for(&measurement)?;
    let role = doc.pcr(3).ok_or(NitroError::ParentRole)?;
    if !manifest.parent_roles().contains(role) {
        return Err(NitroError::ParentRole);
    }
    if image.version() < own.version() {
        return Err(NitroError::Downgrade);
    }
    let x25519 = doc
        .public_key()
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
        .ok_or(NitroError::PublicKey)?;
    Ok(HandoffPeer {
        image,
        measurement,
        x25519,
    })
}

/// A holder that passed [`verify_handoff_holder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffHolder<'m> {
    /// Its image in the manifest.
    pub image: &'m ManifestImage,
    /// Its PCRs.
    pub measurement: Measurement,
}

/// ADR 0051 §4.2 step 3: what a joining enclave checks of the holder before
/// it takes a seed from it. Steps 2–4 and 6 of §2.2, plus: `nonce` is the
/// joiner's, and PCR3 is one of the manifest's `parent_roles`.
///
/// Unlike [`verify_handoff_peer`] it neither asks for a `public_key` nor
/// refuses an older image: in a rolling upgrade the holder runs the older
/// image (§7.4), and the holder is the one that refuses a downgrade. That
/// the manifest is the published one is the caller's check (§4.2).
pub fn verify_handoff_holder<'m>(
    document: &[u8],
    manifest: &'m VerifiedManifest,
    nonce: &[u8],
    now_ms: u64,
) -> Result<HandoffHolder<'m>, NitroError> {
    verify_handoff_holder_with_root(document, chain::AWS_NITRO_ROOT_G1, manifest, nonce, now_ms)
}

pub(crate) fn verify_handoff_holder_with_root<'m>(
    document: &[u8],
    root: &[u8],
    manifest: &'m VerifiedManifest,
    nonce: &[u8],
    now_ms: u64,
) -> Result<HandoffHolder<'m>, NitroError> {
    let doc = verify_document_with_root(document, root, now_ms)?;
    doc.check_fresh(nonce, now_ms)?;
    let measurement = doc.measurement()?;
    let image = manifest.image_for(&measurement)?;
    let role = doc.pcr(3).ok_or(NitroError::ParentRole)?;
    if !manifest.parent_roles().contains(role) {
        return Err(NitroError::ParentRole);
    }
    Ok(HandoffHolder { image, measurement })
}
